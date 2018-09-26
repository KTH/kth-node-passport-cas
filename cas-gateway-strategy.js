'use strict'

const PassportStrategy = require('passport-strategy')
const util = require('util')
const url = require('url')
const request = require('request')
const xml2js = require('xml2js')
const log = require('kth-node-log')

const defaults = {
  casUrl: '',
  parseCasXml: xml2js.parseString,
  request: request,
  maxAttempts: 2,
  anonymous: 'anonymous-user'
}

function GatewayStrategy (options, verify) {
  if (!(this instanceof GatewayStrategy)) {
    return new GatewayStrategy(options, verify)
  }

  if (typeof options === 'function') {
    verify = options
    options = {
      casUrl: defaults.casUrl,
      parseCasXml: defaults.parseCasXml,
      request: defaults.request,
      maxAttempts: defaults.maxAttempts,
      anonymous: defaults.anonymous
    }
  }

  this.name = 'cas-gateway'
  this.verify = verify
  this.parseCasXml = options.parseCasXml || defaults.parseCasXml
  this.request = options.request || defaults.request
  this.anonymous = options.anonymous || defaults.anonymous
  this.maxAttempts = options.maxAttempts || defaults.maxAttempts
  this.casUrl = options.casUrl
  this.loginUrl = url.resolve(this.casUrl, '/login')
  this.serviceValidateUrl = url.resolve(this.casUrl, '/serviceValidate')

  if (typeof this.verify !== 'function') {
    throw new TypeError('GatewayStrategy requires a verify callback')
  }

  if (typeof this.parseCasXml !== 'function') {
    throw new TypeError('GatewayStrategy requires xml2js')
  }

  if (typeof this.request !== 'function') {
    throw new TypeError('GatewayStrategy requires request')
  }

  if (typeof this.anonymous !== 'string') {
    throw new TypeError('GatewayStrategy requires a fallback username for anonymous users')
  }

  if (typeof this.maxAttempts !== 'number' || this.maxAttempts < 1) {
    throw new TypeError('GatewayStrategy requires a positive number for max attempts')
  }

  if (!this.casUrl) {
    throw new TypeError('GatewayStrategy requires a CAS URL')
  }

  PassportStrategy.call(this)
}

util.inherits(GatewayStrategy, PassportStrategy)

function _getProto(headerStr) {
  if (typeof headerStr !== 'string') return undefined

  const tmp = headerStr.split(',')
  if (tmp.length <= 0) return undefined

  return tmp[0].trim()
}

GatewayStrategy.prototype.authenticate = function (req, options) {
  log.debug('CasGateway: Auth for ticket')
  const ticket = req.query.ticket
  const loginUrl = url.parse(this.loginUrl, true)
  let serviceUrl

  if (req.headers['x-forwarded-proto']) {
    serviceUrl = _getProto(req.headers['x-forwarded-proto']) + '://' + req.get('host') + req.originalUrl
  } else {
    serviceUrl = _getProto(req.protocol) + '://' + req.get('host') + req.originalUrl
  }

  log.debug('CasGateway: serviceUrl=', serviceUrl)

  if (!ticket) {
    log.debug('CasGateway: No ticket found')
    if (req.session.gatewayAttempts === 2) {
      log.debug('CasGateway: Reached max number of retries.', req.session.gatewayAttempts)
      return this.success(this.anonymous)
    }

    delete loginUrl.search

    loginUrl.query = {
      gateway: true,
      service: serviceUrl
    }

    if (!req.session.gatewayAttempts) {
      log.debug('CasGateway: session.gatewayAttempts is undefined, first auth try')
      req.session.gatewayAttempts = 1
    } else {
      req.session.gatewayAttempts += 1
      log.debug('CasGateway: Retrying auth', req.session.gatewayAttempts)
    }

    return new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) {
          reject(err)
        } else {
          resolve()
        }
      })
    }).then(res => {
      return this.redirect(url.format(loginUrl))
    })
  }
  log.debug('CasGateway: Ticket found, resetting session.gatewayAttempts')
  req.session.gatewayAttempts = 0

  this.validateService(ticket, serviceUrl)
}

GatewayStrategy.prototype.validateService = function (ticket, serviceUrl) {
  const serviceValidateUrl = url.parse(this.serviceValidateUrl, true)

  const parsedServiceUrl = url.parse(serviceUrl, true)
  delete parsedServiceUrl.search
  parsedServiceUrl.query = {
    nextUrl: parsedServiceUrl.query.nextUrl
  }

  serviceValidateUrl.query = {
    ticket: ticket,
    service: url.format(parsedServiceUrl)
  }

  this.request({
    url: url.format(serviceValidateUrl),
    method: 'GET'
  }, (err, response, body) => {
    if (err) {
      return this.error(err)
    }

    this.parseResponse(body, (err, username) => {
      if (err) {
        return this.error(err)
      }

      this.verify({ status: true, user: username, ticket: ticket }, this.verified.bind(this))
    })
  })
}

GatewayStrategy.prototype.verified = function (err, user, info) {
  if (err) {
    return this.error(err)
  }

  if (!user) {
    return this.fail(info)
  }

  this.success(user, info)
}

GatewayStrategy.prototype.parseResponse = function (xml, callback) {
  this.parseCasXml(xml, (err, result) => {
    if (err) {
      return callback(err)
    }

    const response = _prop(result, 'cas:serviceResponse')
    if (!response) {
      return callback(new Error('Badly formatted response'))
    }

    const failure = _prop(_head(_prop(response, 'cas:authenticationFailure')), '_')
    if (failure) {
      return callback(new Error(failure))
    }

    const username = _head(_prop(_head(_prop(response, 'cas:authenticationSuccess')), 'cas:user'))
    if (username) {
      return callback(null, username)
    }

    return callback(new Error('No username found'))
  })
}

function _head (array) {
  if (array && array.length) {
    return array[ 0 ]
  }

  return null
}

function _prop (obj, key) {
  if (obj && obj[ key ]) {
    return obj[ key ]
  }

  return null
}

module.exports = {
  Strategy: GatewayStrategy
}
