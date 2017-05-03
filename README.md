# kth-node-passport-cas
Cas authentication strategy for Passport based but modified from github.com/sadne/passport-cas.

## API

### Strategy ### 
Passport style authentication strategy implemented for login through KTH CAS.

Usage:

```JavaScript
const passport = require('passport')
const Strategy = require('kth-node-passport-cas').Strategy
const log = require('kth-node-log')

const casOptions = {
  ssoBaseURL: 'https://url.to/cas',
  serverBaseURL: 'http://url.to.me:port',
  log: log
}

const strategy = new Strategy(casOptions,
  function (logOnResult, done) {
    return done(null, logOnResult.user, logOnResult)
  }
)

passport.use(strategy)
```

### GatewayStrategy ###
Passport style authentication strategy implemented to check if user is logged in through KTH CAS.

```JavaScript
const passport = require('passport')
const GatewayStrategy = require('kth-node-passport-cas').GatewayStrategy
const log = require('kth-node-log')

passport.use(new GatewayStrategy({
  casUrl: 'https://url.to/cas'
}, function (result, done) {
  done(null, result.user, result)
}))
```

### getProxyTicket ###
Get a proxy ticket from CAS-service. Returns a promise.

Call signature:

```
const getProxyTicket = require('kth-node-passport-cas').getProxyTicket

getProxyTicket (casService, pgtId, targetService)
  .then((ticket) => {
    // do something...
  })
  .catch((err) => {
    // do something...
  })
```


### Express Route Handlers ###
Express route handlers used for KTH CAS authentication.

```JavaScript
const ldapConfig = { ... } // Object structure can be found in kth-node-configuration

const ldap = require('kth-node-ldap')
const ldapClient =  ldap.createClient({
  url: ldapConfig.uri,
  timeout: ldapConfig.timeout,
  connectTimeout: ldapConfig.connecttimeout,
  maxConnections: ldapConfig.maxconnections,
  bindDN: ldapConfig.username,
  bindCredentials: ldapConfig.password,
  checkInterval: ldapConfig.checkinterval,
  maxIdleTime: ldapConfig.maxidletime,
  reconnect: true
})

const server = require('kth-node-server')
const passport = require('passport')

// Don't forget to register the strategies here (Strategy and GatewayStrategy shown above)

server.use(passport.initialize())
server.use(passport.session())

const { authLoginHandler, authCheckHandler, logoutHandler, pgtCallbackHandler, serverLogin, getServerGatewayLogin } = require('kth-node-passport-cas').routeHandlers({
  adminGroup: 'group_name', // LDAP admin group for this app
  proxyPrefixPathUri: '/app/mountpoint',
  casLoginUri: '/app/mountpoint/login',
  casGatewayUri: '/app/mountpoint/loginGateway',
  ldapConfig: ldapConfig,
  ldapClient: ldapClient,
  server: server
})
appRoute.get('cas.login', '/app/mountpoint/login', authLoginHandler)
appRoute.get('cas.gateway', '/app/mountpoint/loginGateway', authCheckHandler)
appRoute.get('cas.logout', '/app/mountpoint/logout', logoutHandler)
// Optional pgtCallback
appRoute.get('cas.pgtCallback', '/app/mountpoint/pgtCallback', pgtCallbackHandler)

// Make sure user is logged in and send to login page if not
server.get('/app/mountpoint', serverLogin, function (req, res) { ... })

// Make sure user is logged in and fail request if not
server.get('/app/mountpoint/gateway', getServerGatewayLogin('/'), function (req, res) { ... })
```
