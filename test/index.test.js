/* eslint-disable no-unused-expressions */
const feathers = require('@feathersjs/feathers');
const expressify = require('@feathersjs/express');
const authentication = require('@feathersjs/authentication');
const memory = require('feathers-memory');
const chai = require('chai');
const sinon = require('sinon');
const sinonChai = require('sinon-chai');
const passportCas = require('../lib/cas');

const cas = require('../lib');
// const Strategy = require('./fixtures/strategy');

const { Verifier } = cas;
const { expect } = chai;

chai.use(sinonChai);

describe('@rula/feathers-authentication-cas', () => {
  it('is CommonJS compatible', () => {
    expect(typeof require('../lib')).to.equal('function');
  });

  it('basic functionality', () => {
    expect(typeof cas).to.equal('function');
  });

  it('exports default', () => {
    expect(cas.default).to.equal(cas);
  });

  it('exposes the Verifier class', () => {
    expect(typeof Verifier).to.equal('function');
    expect(typeof cas.Verifier).to.equal('function');
  });

  describe('initialization', () => {
    let app;
    // let config;
    let globalConfig;
    let casConfig;
    // let user;

    beforeEach(() => {
      casConfig = {
        casUrl: 'https://localhost:3030/cas',
        serviceBaseUrl: 'https://localhost:3030',
        name: 'cas',
        servicePath: '/login/validate',
        path: '/login',
        version: '1.0',
        useSaml: false
      };

      globalConfig = {
        passReqToCallback: false,
        secret: 'supersecret',
        service: 'users',
        entity: 'user',
        cas: {
          path: '1234',
          clientSecret: 'secret',
          scope: ['user']
        }
      };

      app = expressify(feathers());
      app.set('host', 'localhost');
      app.set('port', 8080);
      app.use('/users', memory());
      app.configure(authentication(globalConfig));

      // user = app.service('users').create({
      //   userId: 1,
      //   username: 'mockey'
      // });
    });

    it('throws an error if passport has not been registered', () => {
      expect(() => {
        expressify(feathers()).configure(cas());
      }).to.throw();
    });

    it('throws an error if casUrl is missing', () => {
      expect(() => {
        delete casConfig.casUrl;
        app.configure(cas(casConfig));
      }).to.throw();
    });

    it('registers the cas passport strategy', () => {
      sinon.spy(app.passport, 'use');
      sinon.spy(passportCas, 'Strategy');
      app.configure(cas(casConfig));
      app.setup();

      expect(passportCas.Strategy).to.have.been.calledOnce;
      expect(app.passport.use).to.have.been.calledWith(casConfig.name);

      app.passport.use.restore();
      passportCas.Strategy.restore();
    });

    it('registers the strategy options', () => {
      sinon.spy(app.passport, 'options');
      app.configure(cas(casConfig));
      app.setup();

      expect(app.passport.options).to.have.been.calledOnce;

      app.passport.options.restore();
    });

    it('registers the redirect options on strategy options', () => {
      sinon.spy(authentication.express, 'authenticate');

      const mergedOptions = Object.assign({}, casConfig, globalConfig);
      app.configure(cas(mergedOptions));
      app.setup();

      delete mergedOptions.Strategy;
      expect(authentication.express.authenticate).to.have.been.calledWith(casConfig.name, sinon.match(mergedOptions));

      authentication.express.authenticate.restore();
    });

    it('registers express get route', () => {
      sinon.spy(app, 'get');
      app.configure(cas(casConfig));
      app.setup();

      expect(app.get).to.have.been.calledWith(`/login`);

      app.get.restore();
    });

    it('registers express validation route', () => {
      sinon.spy(app, 'get');
      app.configure(cas(casConfig));
      app.setup();

      expect(app.get).to.have.been.calledWith(`/login/validate`);

      app.get.restore();
    });

    describe('custom Verifier', () => {
      it('throws an error if a verify function is missing', () => {
        expect(() => {
          class CustomVerifier {
            constructor (app) {
              this.app = app;
            }
          }
          casConfig.Verifier = CustomVerifier;
          app.configure(cas(casConfig));
          app.setup();
        }).to.throw();
      });
    });
  });
});
