# Grav LoginLdap Plugin

The **loginldap plugin** for [Grav](http://github.com/getgrav/grav) adds the ability to authenticate against an LDAP server to Grav.  It is based on the [Grav Login Plugin](https://github.com/getgrav/grav-plugin-login) and is compatible with ACL roles defined for the login plugin.  However, it is meant to replace the login plugin; you cannot currently have both **login** and **loginldap** enabled.

# Installation

The **loginldap** plugin actually requires the help of the **form** plugin.  The **form** plugin is used to generate the forms required.  If you have the **login** plugin installed, you must uninstall or disable it before using **loginldap**.  To install, run:

```
$ bin/gpm install loginldap
```


# Usage

You can add ACL to any page by typing something like below into the page header:

```
access:
  site.login: true
```

Users who have any of the listed ACL roles enabled will have access to the page.
Others will be forwarded to login screen.  All users who successfully authenticate against the LDAP directory will be given the site.login role.

## Create Private Areas

Enabling the setting "Use parent access rules" (`parent_acl` in loginldap.yaml) allows you to create private areas where you set the access level on the parent page, and all the subpages inherit that requirement.

# Login Page

The login plugin can **automatically generate** a login page for you when you try to access a page that your user does not have access to.

Alternatively, you can also provide a specific login route if you wish to forward users to a specific login page. To do this you need to create a copy of the `loginldap.yaml` from the plugin in your `user/config/plugins` folder and provide a specific route (or just edit the plugin setttings in the admin plugin).

```
route: /user-login
```

You would then need to provide a suitable login form, probably based on the one that is provided with the plugin.

## Redirection after Login

By default Grav will redirect to the prior page visited before entering the login process.  Any page is fair game unless you manually set:

```
login_redirect_here: false
```

In the page's header.  If you set this value to `false`, this page will not be a valid redirect page, and the page visited prior to this page will be considered.

You can override this default behavior by forcing a standard location by specifying an explicit option in your Login configuration YAML:

```
redirect_after_login: '/profile'
```

This will always take you to the `/profile` route after a successful login.

# Logout

The loginldap plugin comes with a simple Twig partial to provide a logout link (`login-status.html.twig`).  You will need to include it in your theme however.  An example of this can be found in the Antimatter theme's `partials/navigation.html.twig` file:

```
{% if config.plugins.login.enabled and grav.user.username %}
    <li><i class="fa fa-lock"></i> {% include 'partials/login-status.html.twig' %}</li>
{% endif %}
```

Modify it as follows to make it compatible with the loginldap plugin:

```
{% if (config.plugins.login.enabled or config.plugins.loginldap.enabled) and grav.user.username %}
    <li><i class="fa fa-lock"></i> {% include 'partials/login-status.html.twig' %}</li>
{% endif %}
```

You can also copy this `login-status.html.twig` file into your theme and modify it as you see fit.
