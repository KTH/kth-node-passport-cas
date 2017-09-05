'use strict'

const passport = require('passport')
const log = require('kth-node-log')

module.exports = function (options) {
  const casLoginUri = options.casLoginUri // paths.cas.login.uri
  if (!casLoginUri || typeof casLoginUri !== 'string') throw(Error('Missing options.casLoginUri when setting up route handlers'))

  const casGatewayUri = options.casGatewayUri // paths.cas.gateway.uri
  if (!casGatewayUri || typeof casGatewayUri !== 'string') throw(Error('Missing options.casGatewayUri when setting up route handlers'))
    
  const proxyPrefixPath = options.proxyPrefixPath
  if (!proxyPrefixPath || typeof proxyPrefixPath !== 'string') throw(Error('Missing options.proxyPrefixPath when setting up route handlers'))
  
  const server = options.server
  const cookieTimeout = options.cookieTimeout || 0

  const _protectUrlFromInjection = function (inStr) {
    if (inStr === '/') {
      return inStr
    } else if (inStr.startsWith(proxyPrefixPath)) {
      return inStr
    } else {
      throw(Error('Possible JavaScript-injection vuln during redirect'))
    }
  }

  /**
   * GET request to the login path E.g /login
   */
  function loginHandler (req, res, next) {
    log.debug({ req: req }, '/login called, user: ' + req.user)

    /**
     * Authenticating requests is as simple as calling passport.authenticate() and specifying which strategy to employ.
     * authenticate()'s function signature is standard Connect middleware, which makes it convenient to use as
     * route middleware in Express applications.
     */
    passport.authenticate('cas',

      /*
      * Custom Callback for success. If the built-in options are not sufficient for handling an authentication request,
      * a custom callback can be provided to allow the application to handle success or failure.
      */
      function (err, user, info) {
        if (err) {
          return next(err)
        }

        if (!user) {
          log.debug('No user found, redirecting to /login')
          return res.redirect(casLoginUri)
        }

        req.logIn(user, function (err) {
          if (err) {
            return next(err)
          }
          try {
            // Redirects the authenticated user based on the user group membership.
            log.debug('Redirects the authenticated user based on the user group membership')
            // return redirectAuthenticatedUser(user, res, req, info.pgtIou)
            res.locals.userId = user
            res.locals.pgtIou = info.pgtIou
            return next()
          } catch (err) {
            log.debug('Could not redirect the authenticated user based on the user group membership')
            return next(err)
          }
        })
      }
    )(req, res, next)
  }

  function gatewayHandler (req, res, next) {
    passport.authenticate('cas-gateway', {
      successReturnToOrRedirect: '/',
      failureRedirect: '/error'
    }, function (err, user, info) {
      if (err) {
        return next(err)
      }

      req.logIn(user, function (err) {
        if (err) {
          return next(err)
        }

        if (user === 'anonymous-user') {
          // TODO: potential JS-injection
          res.redirect(_protectUrlFromInjection(req.query['nextUrl']))
          return
        }

        try {
          // return redirectAuthenticatedUser(user, res, req, info && info.pgtIou)
          res.locals.userId = user
          res.locals.pgtIou = info.pgtIou
          return next()
        } catch (err) {
          next(err)
        }
      })
    })(req, res, next)
  }

  /**
   * Logout from application.
   */
  function logoutHandler (req, res) {
    req.logout()

    try {
      delete req.session.ldapDisplayName
      delete req.session.ldapUserName
      delete req.session.ldapEmail
      log.info({ req: req }, 'Log out, destroying session on logout')
    } catch (error) {
      log.info({ req: req, err: error }, 'Error destroying session on logout')
    }

    res.redirect('/')
  }

  function pgtCallbackHandler (req, res) {
    log.debug('CAS pgtCallback')
    if (req.query.pgtIou !== undefined) {
      server.locals.secret[ req.query.pgtIou ] = req.query.pgtId
    }
    res.end('OK')
  }

  /**
   * Check if the user is logged in. If logged in, pass to next,
   * else redirect to the login server.
   *
   * Setting config value ldap.authorizeUser to false will disable
   * authorization, any logged in user will gain access
   */
  function _clearUser (req) {
    delete req.user
    if (req.session.authUser) {
      delete req.session.authUser
    }
  }

  function serverLogin (req, res, next) {
    log.debug({ session: req.session }, 'Login function called. User: ' + req.user)

    if (req.user && req.user === 'anonymous-user') {
      _clearUser(req)
    }

    if (req.user) {
      log.debug('req.user: ' + JSON.stringify(req.user))
      if (req.session.authUser && req.session.authUser.username) {
        log.info({ req: req }, 'User logged in, found ldap user: ' + req.session.authUser.username)
        next()
      } else {
        log.info('unable to find ldap user: ' + req.user)
        res.statusCode = 403
        res.send('403 Not authorized for this resource')
      }
    } else {
      req.nextUrl = req.originalUrl
      log.debug('Next url: ' + req.nextUrl)
      return res.redirect(casLoginUri + '?nextUrl=' + encodeURIComponent(req.nextUrl))
    }
  }

  function serverGatewayLogin (fallback) {
    return (req, res, next) => {
      if (req.session === undefined) {
        log.error('gatewayLogin: sessions unavailable')
        return next(new Error('sessions unavailable'))
      }

      /**
        This hack solves the conflicting demands of directory and profiles
        if a user isn't logged in when viewing a directory page, we don't want to do
        a round trip to the CAS for every request. On the other hand if the user is not
        logged in when viewing a profile page, and then logs in, we do want to send the user
        back to the CAS.
       */
      const time = new Date().getTime() / 1000
      if (req.user && req.user === 'anonymous-user' && time - req.session.time > cookieTimeout) {
        _clearUser(req)
      }
      req.session.time = time

      if (req.session.gatewayAttempts >= 2) {
        log.debug('gatewayLogin: exhausted gateway attempts, allow access as anonymous user')
        log.debug({ session: req.session }, 'gatewayLogin: session')
        req.session.gatewayAttempts = 0 // reset gateway attempts to fix authentication for users not logged in the first time a cookie is set
        next()
        return
      }

      if (req.user) {
        log.debug('gatewayLogin: found user ' + req.user)
        next()
      } else {
        log.debug('gatewayLogin: no user, attempt gateway login')
        req.session.redirectTo = req.originalUrl
        req.session.fallbackTo = fallback
        res.redirect(casGatewayUri + '?nextUrl=' + encodeURIComponent(req.originalUrl))
      }
    }
  }

  return {
    authLoginHandler: loginHandler,
    authCheckHandler: gatewayHandler,
    logoutHandler: logoutHandler,
    pgtCallbackHandler: pgtCallbackHandler,
    serverLogin: serverLogin,
    getServerGatewayLogin: serverGatewayLogin
  }
}

/**
 * Search user using LDAPJS.
 * scope  One of base, one, or sub. Defaults to base.
 * filter  A string version of an LDAP filter (see below), or a programatically constructed Filter object. Defaults to (objectclass=*).
 * attributes  attributes to select and return (if these are set, the server will return only these attributes). Defaults to the empty set, which means all attributes.
 * attrsOnly  boolean on whether you want the server to only return the names of the attributes, and not their values. Borderline useless. Defaults to false.
 * sizeLimit  the maximum number of entries to return. Defaults to 0 (unlimited).
 * timeLimit  the maximum amount of time the server should take in responding, in seconds. Defaults to 10. Lots of servers will ignore this.
 */
module.exports.getRedirectAuthenticatedUser = function (options) {
  const unpackLdapUser = options.unpackLdapUser
  const ldapConfig = options.ldapConfig
  const ldapClient = options.ldapClient

  return function redirectAuthenticatedUser (req, res) {
    const kthid = res.locals.userId
    const pgtIou = res.locals.pgtIou

    var searchFilter = ldapConfig.filter.replace(ldapConfig.filterReplaceHolder, kthid)
    log.debug('Redirecting user with id', {kthId: kthid})
    var searchOptions = {
      scope: ldapConfig.scope,
      filter: searchFilter,
      attributes: ldapConfig.userattrs,
      sizeLimits: ldapConfig.searchlimit,
      timeLimit: ldapConfig.searchtimeout
    }
    ldapClient.searchOne(ldapConfig.base, searchOptions)
    .then((user) => {
      log.debug({ searchEntry: user }, 'LDAP search result')

      if (user) {
        req.session.authUser = unpackLdapUser(user, pgtIou)
        if (req.query['nextUrl']) {
          log.info({ req: req }, `Logged in user (${kthid}) exist in LDAP group, redirecting to ${req.query[ 'nextUrl' ]}`)
        } else {
          log.info({ req: req }, `Logged in user (${kthid}) exist in LDAP group, but is missing nextUrl. Redirecting to /`)
        }
        // TODO: potential JS-injection
        return res.redirect(_protectUrlFromInjection(req.query[ 'nextUrl' ] || '/'))
      } else {
        log.info({ req: req }, `Logged in user (${kthid}), does not exist in required group to /`)
        return res.redirect('/')
      }
    })
    .catch((err) => {
      log.error({ err: err }, 'LDAP search error')
      // Is this really desired behaviour? Would make more sense if we got an error message
      return res.redirect('/')
    })
  }
}
