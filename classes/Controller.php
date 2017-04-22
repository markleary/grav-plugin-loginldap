<?php

namespace Grav\Plugin\LoginLdap;

use Grav\Common\Config\Config;
use Grav\Common\Grav;
use Grav\Plugin\LoginLdap\RememberMe;
use Grav\Common\Language\Language;
use Grav\Common\User\User;
use Grav\Common\Utils;

use Birke\Rememberme\Cookie;
use RocketTheme\Toolbox\Session\Message;

/**
 * Class Controller
 * @package Grav\Plugin\LoginLdap
 */
class Controller
{
    /**
     * @var \Grav\Common\Grav
     */
    public $grav;

    /**
     * @var string
     */
    public $action;

    /**
     * @var array
     */
    public $post;

    /**
     * @var string
     */
    protected $redirect;

    /**
     * @var int
     */
    protected $redirectCode;

    /**
     * @var string
     */
    protected $prefix = 'task';

    /**
     * @var \Birke\Rememberme\Authenticator
     */
    protected $rememberMe;

    /**
     * @var resource
     */
    protected $ldap;

    /**
     * @var Login
     */
    protected $login;

    /**
     * @param Grav   $grav
     * @param string $action
     * @param array  $post
     */
    public function __construct(Grav $grav, $action, $post = null)
    {
        $this->grav = $grav;
        $this->action = $action;
        $this->post = $this->getPost($post);

        $this->rememberMe();

        // Get LDAP config
        $config = $this->grav['config']->get('plugins.loginldap.ldap');

        // Connect to ldap server
        $this->open($config['server'], $config['port'], $config['ssl_start_tls'], $config['ssl_verify']);

        // Bind
        if ($config['bind_type'] == 'user') {
            $this->userbind($config['bind_dn'], $config['bind_pw']);
        } elseif ($config['bind_type'] == 'anonymous') {
            $this->anonbind();
        } else {
            throw new \RuntimeException($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.INVALID_BIND_PARAM'));
        }
    }

    function __destruct() {
        if ($this->ldap) {
          // Kill LDAP connection
          @ldap_unbind($this->ldap);
        }
    }

    /**
     * Performs an action.
     */
    public function execute()
    {
        // Set redirect if available.
        if (isset($this->post['_redirect'])) {
            $redirect = $this->post['_redirect'];
            unset($this->post['_redirect']);
        }

        $success = false;
        $method = $this->prefix . ucfirst($this->action);

        if (!method_exists($this, $method)) {
            throw new \RuntimeException('Page Not Found', 404);
        }

        try {
            $success = call_user_func([$this, $method]);
        } catch (\RuntimeException $e) {
            $this->setMessage($e->getMessage(), 'error');
        }

        if (!$this->redirect && isset($redirect)) {
            $this->setRedirect($redirect);
        }

        return $success;
    }

    /**
     * Handle login.
     *
     * @return bool True if the action was performed.
     */
    public function taskLogin()
    {
        /** @var Language $t */
        $t = $this->grav['language'];
        if ($this->authenticate($this->post)) {
            $this->setMessage($t->translate('PLUGIN_LOGIN_LDAP.LOGIN_SUCCESSFUL'));

            $redirect = $this->grav['config']->get('plugins.loginldap.redirect_after_login');
            if (!$redirect) {
                $redirect = $this->grav['session']->redirect_after_login ?: $this->grav['uri']->referrer('/');
            }
            $this->setRedirect($redirect);
        } else {
            $user = $this->grav['user'];
            if ($user->username) {
                $this->setMessage($t->translate('PLUGIN_LOGIN_LDAP.ACCESS_DENIED'), 'error');
            } else {
                $this->setMessage($t->translate('PLUGIN_LOGIN_LDAP.LOGIN_FAILED'), 'error');
            }
        }

        return true;
    }

    /**
     * Handle logout.
     *
     * @return bool True if the action was performed.
     */
    public function taskLogout()
    {
        /** @var User $user */
        $user = $this->grav['user'];

        if (!$this->rememberMe->login()) {
            $credentials = $user->get('username');
            $this->rememberMe->getStorage()->cleanAllTriplets($credentials);
        }
        $this->rememberMe->clearCookie();

        $this->grav['session']->invalidate()->start();
        $this->setRedirect('/');

        $this->grav['log']->debug('User ' . $user->get('username') . ' logged out.');
        return true;
    }

    /**
     * Authenticate user.
     *
     * @param array $form Form fields.
     *
     * @return bool
     */
    protected function authenticate($form)
    {
        $authenticated = false;

        $user = $this->grav['user'];

        if (!$user->authenticated) {
            //$username = isset($form['username']) ? $form['username'] : $this->rememberMe->login();
            $username = $form['username'];
            if (!$username) {
              return false;
            }

            // Get LDAP config
            $config = $this->grav['config']->get('plugins.loginldap.ldap');

            $dataUser = $this->loaduser($username);

            if ($dataUser) {
                if (! @ldap_bind($this->ldap, $dataUser['dn'], $this->post['password'])) {
                    $this->grav['log']->debug('LDAP authentication failed for user ' . $username . '.');
                    // User exists, bad password
                    return false;
                }
            } else {
                // User does not exist
                $this->grav['log']->debug('User ' . $username . ' not found in LDAP directory.');
                return false;
            }

            $user = new User($dataUser);
            $authenticated = true;
            $user->authenticated = true;

            // Authorize against user ACL
            $user_authorized = $user->authorize('site.login');

            if ($user_authorized) {
                $this->grav['session']->user = $user;

                unset($this->grav['user']);
                $this->grav['user'] = $user;

                $this->grav['log']->debug('User ' . $username . ' logged in.');

                // If the user wants to be remembered, create Rememberme cookie
                if (!empty($form['rememberme'])) {
                    $this->grav['log']->debug('RememberMe cookie set for ' . $form['username']);
                    $this->rememberMe->createCookie($form['username']);
                } else {
                    $this->rememberMe->clearCookie();
                    $this->rememberMe->getStorage()->cleanAllTriplets($user->get('username'));
                }

            }
        }

        // Authorize against user ACL
        $user_authorized = $user->authorize('site.login');
        $user->authenticated = ($user->authenticated && $user_authorized);

        return $user->authenticated;
    }

    public function loaduser($username = null) {

        if (!$username) {
          return false;
        }

        // Get LDAP config
        $config = $this->grav['config']->get('plugins.loginldap.ldap');

        // Build attribute array
        $ldapattr = array_values($config['attr']);
        array_push($ldapattr, 'dn');

        // Build search filter
        $sf = str_replace('%s', $username, $config['user_filter']);

        $ldapuser = $this->search($config['user_base_dn'], $sf, $ldapattr);

        if (!$ldapuser) {
            // User does not exist
            return false;
        }

        $dataUser= array(
            'username' => $username,
            'dn' => $ldapuser['dn'],
            'fullname' => $ldapuser[$config['attr']['fullname']][0],
            // Give all users site access role
            'access' => array('site' => array('login' => 'true')),
            'language' => 'en',
        );

        // Assign any additional roles
        $rolemap = $this->grav['config']->get('plugins.loginldap.rolemap');
        if ((is_array($rolemap)) && (isset($ldapuser[$config['attr']['groups']]))) {
            foreach ($rolemap as $role => $value) {
                if (is_string($value)) {
                    if (in_array($value, $ldapuser[$config['attr']['groups']])) {
                        $dataUser['access'][$role] = array('login' => 'true');
                    }
                } elseif (is_array($value)) {
                    $accessGroup = null;
                    foreach($value as $roleChild => $ldapgroup) {
                        if (in_array($ldapgroup, $ldapuser[$config['attr']['groups']])) {
                            if (!isset($accessGroup)) {
                                $accessGroup = array($roleChild => 'true');
                            } else {
                                $accessGroup[$roleChild] = 'true';
                            }
                        }
                    }

                    if (isset($accessGroup))
                        $dataUser['access'][$role] = $accessGroup;
                }
            }
        }

        // Set email field if in LDAP
        if (isset($ldapuser[$config['attr']['email']])) {
            $dataUser['email'] = $ldapuser[$config['attr']['email']][0];
        }

        return $dataUser;
    }

    /**
     * Redirects an action
     */
    public function redirect()
    {
        if ($this->redirect) {
            $this->grav->redirect($this->redirect, $this->redirectCode);
        }
    }

    /**
     * Set redirect.
     *
     * @param     $path
     * @param int $code
     */
    public function setRedirect($path, $code = 303)
    {
        $this->redirect = $path;
        $this->redirectCode = $code;
    }

    /**
     * Add message into the session queue.
     *
     * @param string $msg
     * @param string $type
     */
    public function setMessage($msg, $type = 'info')
    {
        /** @var Message $messages */
        $messages = $this->grav['messages'];
        $messages->add($msg, $type);
    }

    /**
     * Gets and sets the RememberMe class
     *
     * @param  mixed $var A rememberMe instance to set
     *
     * @return RememberMe\RememberMe Returns the current rememberMe instance
     */
    public function rememberMe($var = null)
    {
        if ($var !== null) {
            $this->rememberMe = $var;
        }

        if (!$this->rememberMe) {
            /** @var Config $config */
            $config = $this->grav['config'];

            // Setup storage for RememberMe cookies
            $storage = new RememberMe\TokenStorage();
            $this->rememberMe = new RememberMe\RememberMe($storage);
            $this->rememberMe->setCookieName($config->get('plugins.loginldap.rememberme.name'));
            $this->rememberMe->setExpireTime($config->get('plugins.loginldap.rememberme.timeout'));

            // Hardening cookies with user-agent and random salt or
            // fallback to use system based cache key
            $server_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown';
            $data = $server_agent . $config->get('security.salt', $this->grav['cache']->getKey());
            $this->rememberMe->setSalt(hash('sha512', $data));

            // Set cookie with correct base path of Grav install
            $cookie = new Cookie();
            $cookie->setPath($this->grav['base_url_relative'] ?: '/');
            $this->rememberMe->setCookie($cookie);
        }

        return $this->rememberMe;
    }

    /**
     * Prepare and return POST data.
     *
     * @param array $post
     *
     * @return array
     */
    protected function &getPost($post)
    {
        unset($post[$this->prefix]);

        // Decode JSON encoded fields and merge them to data.
        if (isset($post['_json'])) {
            $post = array_merge_recursive($post, $this->jsonDecode($post['_json']));
            unset($post['_json']);
        }

        return $post;
    }

    /**
     * Establish connection to server
     */
     protected function open($server, $port, $tls, $verify)
     {
         if (! function_exists('ldap_connect')) {
             throw new \RuntimeException($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.EXT_MISSING'));
         }

         if (! $verify) {
             putenv('LDAPTLS_REQCERT=never');
         }
         $this->ldap = @ldap_connect($server, $port);
         if ($this->ldap === false) {
             throw new \RuntimeException($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.NO_CONNECT'));
         }
         ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
         ldap_set_option($this->ldap, LDAP_OPT_REFERRALS, 0);
         ldap_set_option($this->ldap, LDAP_OPT_NETWORK_TIMEOUT, 1);
         ldap_set_option($this->ldap, LDAP_OPT_TIMELIMIT, 1);
         if ($tls && ! @ldap_start_tls($this->ldap)) {
             throw new \RuntimeException($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.NO_TLS'));
         }
         return true;
     }

     /**
      * Bind to ldap server
      */
     protected function userbind($bind_dn, $bind_password)
     {
         if (! @ldap_bind($this->ldap, $bind_dn, $bind_password)) {
             throw new \RuntimeException($this->grav['language']->translate(['PLUGIN_LOGIN_LDAP.NO_USER_BIND', $bind_dn]));
         }
         return true;
     }

     /**
      * Perform anonymous bind
      */
    protected function anonbind()
    {
        if (! @ldap_bind($this->ldap)) {
            throw new \RuntimeException($this->grav['language']->translate('PLUGIN_LOGIN_LDAP.NO_ANON_BIND'));
        }
        return true;
    }

    /**
     * Perform ldap search, return first result or false if no results
     */
    protected function search($base, $filter, array $attributes, $debug = false)
    {
        if ($debug) {
            $this->grav['debugger']->addMessage('LDAP Base DN='.$base);
            $this->grav['debugger']->addMessage('LDAP Filter='.$filter);
            $this->grav['debugger']->addMessage('LDAP Attributes='.implode(', ', $attributes));
        }
        $sr = ldap_search($this->ldap, $base, $filter, $attributes);
        if ($sr === false) {
            return false;
        }
        $entries = ldap_get_entries($this->ldap, $sr);
        if ($entries === false || count($entries) === 0 || $entries['count'] == 0) {
            return false;
        }

      // Return first result
      return $entries[0];
    }

    /**
     * Recursively JSON decode data.
     *
     * @param  array $data
     *
     * @return array
     */
    protected function jsonDecode(array $data)
    {
        foreach ($data as &$value) {
            if (is_array($value)) {
                $value = $this->jsonDecode($value);
            } else {
                $value = json_decode($value, true);
            }
        }

        return $data;
    }
}
