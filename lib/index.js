const Debug = require('debug');
const { merge, omit, pick } = require('lodash');

const auth = require('@feathersjs/authentication');

const DefaultVerifier = require('./verifier');
const passportCas = require('./cas');

const defaultHandler = require('./express/handler');
const defaultErrorHandler = require('./express/error-handler');

const debug = Debug('@rula/feathers-authentication-cas');
const defaults = {
  name: 'cas',
  server: {
    serviceBaseUrl: 'https://localhost:8080',
    version: '3.0',
    path: '/login',
    servicePath: '/cas/validate',
    failureRedirect: '/login',
    successRedirect: '/',
  },
};

const KEYS = [
  'entity',
  'service'
]

// Export cas-auth init function
function init (options = {}) {
  return function casAuth () {
    const app = this;
    const _super = app.setup;
    const { Strategy } = passportCas;

    if (!app.passport) {
      throw new Error('Can not find app.passport. Did you initialize feathers-authentication before feathers-authentication-cas?');
    }

    if (!options.casUrl) {
      throw new Error('CAS Authentication requires a casUrl to be specified.');
    }

    // Construct casSettings for passport ldap strategy
    let name = options.name || defaults.name;
    let authOptions = app.get('auth') || {};
    let casOptions = authOptions[name] || {};
    const casSettings = merge({}, defaults, pick(authOptions, KEYS), casOptions, omit(options, ['Verifier']));
    const Verifier = options.Verifier || DefaultVerifier;

    const handler = options.handler || defaultHandler(casSettings);
    const errorHandler = defaultErrorHandler(casSettings);

    debug(`Registering '${name}' Express CAS middleware.`);
    app.get(casSettings.path, auth.express.authenticate(name, casSettings));
    app.get(casSettings.servicePath,
      auth.express.authenticate(name, casSettings),
      handler,
      errorHandler,
      auth.express.emitEvents(authOptions),
      auth.express.setCookie(authOptions),
      auth.express.successRedirect(),
      auth.express.failureRedirect(authOptions)
    );

    // plugin setup: register strategy in feathers passport
    app.setup = function () {
      // be sure feathers setup was called
      let result = _super.apply(this, arguments);
      let verifier = new Verifier(app, casSettings);

      if (!verifier.verify) {
        throw new Error('Your verifier must implement a "verify" function. It should have the same signature as function(request, user, done)');
      }

      // Register 'cas' strategy with passport
      debug('Registering cas authentication strategy with options:', casSettings);
      app.passport.use(casSettings.name, new Strategy(casSettings, verifier.verify.bind(verifier)));
      app.passport.options(casSettings.name, casSettings); // do we need this ??

      return result;
    };
  };
}

module.exports = init;

// Exposed Modules
Object.assign(init, {
  defaults,
  default: init,
  Verifier: DefaultVerifier,
});