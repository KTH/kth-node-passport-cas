/**
 * Cas
 */
var url = require("url");
var http = require("http");
var https = require("https");
var passport = require("passport");
var jsdom = require("jsdom");

// query parameter used to request a gateway SSO
var gatewayParameter = "useGateway=true";

/**
 * Creates an instance of `Strategy`.
 */
function Strategy(options, verify) {
  if (typeof options === "function") {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new Error("cas authentication strategy requires a verify function");
  }

  this.ssoBase = options.ssoBaseURL;
  this.pgtUrl = options.pgtURL;
  this.serverBaseURL = options.serverBaseURL;
  this.parsed = url.parse(this.ssoBase);
  if (this.parsed.protocol === "http:") {
    this.client = http;
  } else {
    this.client = https;
  }

  passport.Strategy.call(this);

  this.name = "cas";
  this._verify = verify;
}

/**
 * Authenticate request.
 *
 * @param req The request to authenticate.
 */
Strategy.prototype.authenticate = function(req) {
  var origUrl = req.originalUrl;
  var ticket = req.query.ticket;
  var service = url.resolve(this.serverBaseURL, origUrl);

  // check if gateway SSO requested, remove any
  // gateway query parameter from URL
  var serviceUrl = url.parse(service, true);
  delete serviceUrl.search;
  service = stripGatewayAuthenticationParameter(serviceUrl);

  if (!ticket) {
    // Building the redirect url to the login server
    var loginServerURL = url.parse(this.ssoBase + "/login", true);

    // Adding the gateway parameter if requested
    if (useGatewayAuthentication(req)) {
      loginServerURL.query.gateway = true;
    }

    // Adding the service parameter
    loginServerURL.query.service = service;

    // Redirecting to the login server.
    return this.redirect(url.format(loginServerURL));
  }

  // Formatting the service url and adding the nextUrl parameter after it's done due to double encoding
  // Adding the service parameter
  // Re-creates the original service URL.
  // Remove search and ticket since they are not valid now
  var baseServiceUrl = url.resolve(this.serverBaseURL, origUrl);
  var tmpUrl = url.parse(baseServiceUrl, true);
  delete tmpUrl.search;
  delete tmpUrl.query.ticket;
  var nextUrl = stripGatewayAuthenticationParameter(tmpUrl);
  var validateService = nextUrl;

  var self = this;

  /*
   * Verifies the user login add set error, fail or success depending on the result.
   */
  var verified = function(err, user, info) {
    if (err) {
      return self.error(err);
    }
    if (!user) {
      return self.fail(info);
    }
    self.success(user, info);
  };

  /**
   * Request the login server's /validate with the ticket and service parameters.
   * The callback function handles the CAS server response.
   * Read more at the "CAS protocol section 2.4.2": http://www.jasig.org/cas/protocol
   *
   * Response on ticket validation success:
   * yes
   * u1foobar
   *
   * Response on ticket validation failure:
   * no
   */
  var get = this.client.get(
    {
      host: this.parsed.hostname,
      port: this.parsed.port,
      path: url.format({
        pathname: "/serviceValidate",
        query: {
          ticket: ticket,
          service: validateService,
          pgtUrl: this.pgtUrl
        }
      })
    },
    function(response) {
      response.setEncoding("utf8");
      var body = "";

      response.on("data", function(responseData) {
        body += responseData;
      });

      return response.on("end", function() {
        var parsedResult = parseCasResponse(body, ticket);
        return parsedResult
          .then(function(validationResult) {
            return self._verify(validationResult, verified);
          })
          .catch(function() {
            return self.fail(new Error("The response from the server was bad"));
          });
      });
    }
  );

  get.on("error", function(e) {
    return self.fail(new Error(e));
  });
};

/**
 * Check if we are requested to perform a gateway signon, i.e. a check
 */
function useGatewayAuthentication(req) {
  // can be set on request if via application supplied callback
  if (req.useGateway === true) {
    return true;
  }

  // otherwise via query parameter
  var origUrl = req.originalUrl;
  var useGateway = false;
  var idx = origUrl.indexOf(gatewayParameter);
  if (idx >= 0) {
    useGateway = true;
  }

  return useGateway;
}

/**
 * If a gateway query parameter is added, remove it.
 */
function stripGatewayAuthenticationParameter(aUrl) {
  if (aUrl.query && aUrl.query.useGateway) {
    delete aUrl.query.useGateway;
  }
  if (aUrl.query.nextUrl) {
    var theNextUrl = decodeURIComponent(aUrl.query.nextUrl);
    aUrl.query.nextUrl = decodeURIComponent(theNextUrl);
  }
  var theUrl = url.format(aUrl);

  return theUrl;
}

function parseCasResponse(casResponse, ticket) {
  // Use jsdom to parse the XML repsonse.
  // ( Note:
  //     It seems jsdom currently does not support XML namespaces.
  //     And node names here are case insensitive. Hence attribute
  //     names will also be case insensitive.
  // )
  return new Promise(function(resolve, reject) {
    jsdom.env(casResponse, function(err, window) {
      if (err) {
        return reject(
          new Error("jsdom could not parse casResponse: " + casResponse)
        );
      }

      // Check for auth success
      var elemSuccess = window.document.getElementsByTagName(
        "cas:authenticationSuccess"
      )[0];
      if (elemSuccess) {
        var elemUser = elemSuccess.getElementsByTagName("cas:user")[0];
        if (!elemUser) {
          //  This should never happen
          return reject(new Error("No username?"), false);
        }

        // Got username
        var username = elemUser.textContent;

        // Look for optional proxy granting ticket
        var pgtIOU;
        var elemPGT = elemSuccess.getElementsByTagName(
          "cas:proxyGrantingTicket"
        )[0];
        if (elemPGT) {
          pgtIOU = elemPGT.textContent;
        }

        // Look for optional proxies
        var proxies = [];
        var elemProxies = elemSuccess.getElementsByTagName("cas:proxies");
        for (var i = 0; i < elemProxies.length; i++) {
          var thisProxy = elemProxies[i].textContent.trim();
          proxies.push(thisProxy);
        }

        // Look for optional attributes
        var casResponseParsed = {
          status: true,
          user: username,
          pgtIou: pgtIOU,
          ticket: ticket,
          proxies: proxies
        };

        return resolve(casResponseParsed);
      } // end if auth success

      // Check for correctly formatted auth failure message
      var elemFailure = window.document.getElementsByTagName(
        "cas:authenticationFailure"
      )[0];
      if (elemFailure) {
        var code = elemFailure.getAttribute("code");
        var message = "Validation failed [" + code + "]: ";
        message += elemFailure.textContent;
        return reject(new Error(message), false);
      }

      // The casResponse was not in any expected format, error
      return reject(new Error("Bad casResponse format. " + casResponse));
    });
  });
}

/**
 * Get a proxy ticket using a proxy granting ticket.
 * @param casService - the base URL to the CAS server i.e. without path, e.g. https://login-r.referens.sys.kth.se
 * @param pgtId - the proxy granting ticket to use
 * @param targetService - the service for which the proxy ticket will be used (to validate the ticket you need to supply this service)
 * @returns {Promise} - resolved to a proxy ticket
 * @private
 */
function _getProxyTicket(casService, pgtId, targetService) {
  return new Promise(function(resolve, reject) {
    // setup the url to the CAS Server
    var parsedSsoBase;
    if (typeof casService === "object") {
      var ssoBase = casService.ssoBaseURL;
      parsedSsoBase = url.parse(ssoBase);
    } else if (typeof casService === "string") {
      parsedSsoBase = url.parse(casService);
    }

    var proxyUrl = {
      protocol: "https:",
      hostname: parsedSsoBase.hostname,
      port: parsedSsoBase.port,
      path: url.format({
        pathname: "/proxy",
        query: {
          targetService: targetService,
          pgt: pgtId
        }
      })
    };

    // Query the CAS server
    var req = https.get(proxyUrl, function(res) {
      // Handle server errors
      res.on("error", function(e) {
        return reject(e);
      });

      // Read result
      res.setEncoding("utf8");
      var response = "";
      res.on("data", function(chunk) {
        response += chunk;
        if (response.length > 1e6) {
          req.connection.destroy();
        }
      });

      // Reponse done, finish processing
      res.on("end", function() {
        // Use jsdom to parse the XML response
        jsdom.env(response, function(err, window) {
          // ERROR - unparseable response
          if (err) {
            return reject(new Error("Could not parse response: " + response));
          }

          // OK - Got the proxy ticket
          var elemTicket = window.document.getElementsByTagName(
            "cas:proxyTicket"
          )[0];
          if (elemTicket) {
            var proxyTicket = elemTicket.textContent;
            return resolve(proxyTicket);
          }

          // ERROR - Got a proxy failure
          var elemFailure = window.document.getElementsByTagName(
            "cas:proxyFailure"
          )[0];
          if (elemFailure) {
            var code = elemFailure.getAttribute("code");
            var message = "Proxy failure [" + code + "]: ";
            message += elemFailure.textContent;
            return reject(new Error(message));
          }

          // ERROR - Unexpected response
          return reject(new Error("Bad response format: " + response));
        });
      });
    });
  });
}

/**
 * Expose `Strategy`.
 */
exports.Strategy = Strategy;
exports.getProxyTicket = _getProxyTicket;
