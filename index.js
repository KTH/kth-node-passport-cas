module.exports = {
  Strategy: require('./cas-pgt-strategy').Strategy,
  getProxyTicket: require('./cas-pgt-strategy').getProxyTicket,
  GatewayStrategy: require('./cas-gateway-strategy').Strategy,
  routeHandlers: require('./routeHandlers')
}
