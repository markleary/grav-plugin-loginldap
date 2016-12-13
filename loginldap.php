<?php
namespace Grav\Plugin;

use Grav\Plugin\Admin;
use Grav\Common\Grav;
use Grav\Common\Language\Language;
use Grav\Common\Page\Page;
use Grav\Common\Page\Pages;
use Grav\Common\Plugin;
use Grav\Common\Twig\Twig;
use Grav\Common\User\User;
use Grav\Common\Utils;
use Grav\Common\Uri;
use Grav\Plugin\LoginLdap\Controller;
use Grav\Plugin\Form;
use RocketTheme\Toolbox\Event\Event;
use RocketTheme\Toolbox\Session\Message;

/**
 * Class LoginPlugin
 * @package Grav\Plugin
 */
class LoginLdapPlugin extends Plugin
{
    /** @var string */
    protected $route;

    /** @var string */
    protected $route_register;

    /** @var string */
    protected $route_forgot;

    /** @var bool */
    protected $authenticated = true;

    /** @var bool */
    protected $authorized = true;

    /** @var Login */
    protected $login;

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            'onPluginsInitialized' => [['initializeSession', 10000], ['initializeLogin', 1000]],
            'onTask.login.login'   => ['loginController', 0],
            'onTask.login.logout'  => ['loginController', 0],
            'onPageInitialized'    => ['authorizePage', 0],
            'onPageFallBackUrl'    => ['authorizeFallBackUrl', 0],
            'onTwigTemplatePaths'  => ['onTwigTemplatePaths', 0],
            'onTwigSiteVariables'  => ['onTwigSiteVariables', -100000],
            'onFormProcessed'      => ['onFormProcessed', 0]
        ];
    }

    /**
     * Initialize login plugin if path matches.
     */
    public function initializeSession()
    {
        // Check to ensure sessions are enabled.
        if ($this->grav['config']->get('system.session.enabled') === false) {
            throw new \RuntimeException('The Login plugin requires "system.session" to be enabled');
        }

        // This plugin is meant to be used in place of Login plugin, Login should not be enabled
        if ($this->grav['config']->get('plugins.login.enabled')) {
            throw new \RuntimeException('The Login plugin needs to be disabled.');
        }

        // Autoload classes
        $autoload = __DIR__ . '/vendor/autoload.php';
        if (!is_file($autoload)) {
            throw new \Exception('LoginLdap Plugin failed to load. Composer dependencies not met.');
        }
        require_once $autoload;

        // Define session message service.
        // This is being moved to grav core, will need to remove here
        $this->grav['messages'] = function ($c) {
            $session = $c['session'];

            if (!isset($session->messages)) {
                $session->messages = new Message;
            }

            return $session->messages;
        };


        // Define current user service.
        $this->grav['user'] = function ($c) {
            /** @var Grav $c */

            $session = $c['session'];

            if (!isset($session->user)) {
                $session->user = new User;

                if ($c['config']->get('plugins.loginldap.rememberme.enabled')) {
                    $controller = new Controller($c, 'logincookie');
                    $rememberMe = $controller->rememberMe();

                    // If we can present the correct tokens from the cookie, we are logged in
                    $username = $rememberMe->login();
                    if ($username) {
                        // Load user from ldap
                        $controller->execute();
                    } else {
                        // Check if the token was invalid
                      if ($rememberMe->loginTokenWasInvalid()) {
                          $controller->setMessage($c['language']->translate('PLUGIN_LOGIN_LDAP.REMEMBER_ME_STOLEN_COOKIE'));
                      }
                    }
                }
            }

            return $session->user;
        };
    }

    /**
     * Initialize login plugin if path matches.
     */
    public function initializeLogin()
    {
        /** @var Uri $uri */
        $uri = $this->grav['uri'];

        // Admin has its own login; make sure we're not in admin.
        if (!isset($this->grav['admin'])) {
            $this->route = $this->config->get('plugins.loginldap.route');
        }

        // Register route to login page if it has been set.
        if ($this->route && $this->route == $uri->path()) {
            $this->enable([
                'onPagesInitialized' => ['addLoginPage', 0],
            ]);
            return;
        }

        // If not a known login-related page type...
        $this->enable([
            'onOutputGenerated'    => ['onOutputGenerated', 0]
        ]);
    }

    public function onOutputGenerated()
    {
        $invalid_redirect_routes = [
            $this->config->get('plugins.loginldap.route') ?: '/login',
        ];
        $current_route = $this->grav['uri']->route();
        $allowed = true;

        $header = $this->grav['page']->header();
        if (isset($header->login_redirect_here) && $header->login_redirect_here == false) {
            $allowed = false;
        }

        if (!in_array($current_route, $invalid_redirect_routes) && $allowed) {
            $this->grav['session']->redirect_after_login = $this->grav['uri']->path() . $this->grav['uri']->params();
        }
    }

    /**
     * Add Login page
     */
    public function addLoginPage()
    {
        /** @var Pages $pages */
        $pages = $this->grav['pages'];
        $page = $pages->dispatch($this->route);

        if (!$page) {
            // Only add login page if it hasn't already been defined.
            $page = new Page;
            $page->init(new \SplFileInfo(__DIR__ . "/pages/login.md"));
            $page->slug(basename($this->route));

            $pages->addPage($page, $this->route);
        }
    }


    /**
     * Initialize login controller
     */
    public function loginController()
    {
        /** @var Uri $uri */
        $uri = $this->grav['uri'];
        $task = !empty($_POST['task']) ? $_POST['task'] : $uri->param('task');
        $task = substr($task, strlen('login.'));
        $post = !empty($_POST) ? $_POST : [];

        if (method_exists('Grav\Common\Utils', 'getNonce')) {
            switch ($task) {
                case 'login':
                    if (!isset($post['login-form-nonce']) || !Utils::verifyNonce($post['login-form-nonce'], 'login-form')) {
                        $this->grav['messages']->add($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.ACCESS_DENIED'),
                            'info');
                        $this->authenticated = false;
                        $twig = $this->grav['twig'];
                        $twig->twig_vars['notAuthorized'] = true;

                        return;
                    }
                    break;

                case 'logout':
                    $nonce = $this->grav['uri']->param('logout-nonce');
                    if (!isset($nonce) || !Utils::verifyNonce($nonce, 'logout-form')) {
                        return;
                    }
                    break;

            }
        }

        $controller = new Controller($this->grav, $task, $post);
        $controller->execute();
        $controller->redirect();
    }

    /**
     * Authorize the Page fallback url (page media accessed through the page route)
     */
    public function authorizeFallBackUrl()
    {
        if ($this->config->get('plugins.loginldap.protect_protected_page_media', false)) {
            $page_url = dirname($this->grav['uri']->path());
            $page = $this->grav['pages']->find($page_url);
            $this->grav['page'] = $page;
            $this->authorizePage();
        }
    }

    /**
     * Authorize Page
     */
    public function authorizePage()
    {
        /** @var User $user */
        $user = $this->grav['user'];

        /** @var Page $page */
        $page = $this->grav['page'];

        if (!$page) {
            return;
        }

        $header = $page->header();
        $rules = isset($header->access) ? (array)$header->access : [];

        $config = $this->mergeConfig($page);

        if ($config->get('parent_acl')) {
            // If page has no ACL rules, use its parent's rules
            if (!$rules) {
                $parent = $page->parent();
                while (!$rules and $parent) {
                    $header = $parent->header();
                    $rules = isset($header->access) ? (array)$header->access : [];
                    $parent = $parent->parent();
                }
            }
        }

        // Continue to the page if it has no ACL rules.
        if (!$rules) {
            return;
        }

        // Continue to the page if user is authorized to access the page.
        foreach ($rules as $rule => $value) {
            if (is_array($value)) {
                foreach ($value as $nested_rule => $nested_value) {
                    if ($user->authorize($rule . '.' . $nested_rule) == $nested_value) {
                        return;
                    }
                }
            } else {
                if ($user->authorize($rule) == $value) {
                    return;
                }
            }
        }

        // User is not logged in; redirect to login page.
        if ($this->route && !$user->authenticated) {
            $this->grav->redirect($this->route, 302);
        }

        /** @var Language $l */
        $l = $this->grav['language'];

        // Reset page with login page.
        if (!$user->authenticated) {
            $page = new Page;

            $this->grav['session']->redirect_after_login = $this->grav['uri']->path() . $this->grav['uri']->params();

            // Get the admin Login page is needed, else the default
            if ($this->isAdmin()) {
                $login_file = $this->grav['locator']->findResource("plugins://admin/pages/admin/login.md");
                $page->init(new \SplFileInfo($login_file));
            } else {
                $page->init(new \SplFileInfo(__DIR__ . "/pages/login.md"));
            }

            $page->slug(basename($this->route));
            $this->authenticated = false;

            unset($this->grav['page']);
            $this->grav['page'] = $page;
        } else {
            $this->grav['messages']->add($l->translate('PLUGIN_LOGIN_LDAP.ACCESS_DENIED'), 'error');
            $this->authenticated = false;

            $twig = $this->grav['twig'];
            $twig->twig_vars['notAuthorized'] = true;
        }
    }


    /**
     * Add twig paths to plugin templates.
     */
    public function onTwigTemplatePaths()
    {
        $twig = $this->grav['twig'];
        $twig->twig_paths[] = __DIR__ . '/templates';
    }

    /**
     * Set all twig variables for generating output.
     */
    public function onTwigSiteVariables()
    {
        /** @var Twig $twig */
        $twig = $this->grav['twig'];

        $this->grav->fireEvent('onLoginPage');

        $extension = $this->grav['uri']->extension();
        $extension = $extension ?: 'html';

        if (!$this->authenticated) {
            $twig->template = "login." . $extension . ".twig";
        }

        // add CSS for frontend if required
        if (!$this->isAdmin() && $this->config->get('plugins.loginldap.built_in_css')) {
            $this->grav['assets']->add('plugin://loginldap/css/login.css');
        }

        $task = $this->grav['uri']->param('task');
        $task = substr($task, strlen('login.'));
        if ($task == 'reset') {
            $username = $this->grav['uri']->param('user');
            $token = $this->grav['uri']->param('token');

            if (!empty($username) && !empty($token)) {
                $twig->twig_vars['username'] = $username;
                $twig->twig_vars['token'] = $token;
            }
        }
    }
}
