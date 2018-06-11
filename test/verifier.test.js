/* eslint-disable no-unused-expressions */
const feathers = require('@feathersjs/feathers');
const expressify = require('@feathersjs/express');
const authentication = require('@feathersjs/authentication');

const { Verifier } = require('../lib');

const chai = require('chai');
const sinon = require('sinon');
const sinonChai = require('sinon-chai');

const { expect } = chai;

chai.use(sinonChai);

describe('@rula/feathers-authentication-cas:verifier', () => {
  let service;
  let app;
  let options;
  let verifier;
  let user;
  let profile;

  beforeEach(() => {
    user = { userId: 1, user: 'test.user' };
    profile = { provider: 'CAS', user: 'test.user' };

    service = {
      id: 'id',
      find: sinon.stub().returns(Promise.resolve([user]))
    };

    app = expressify(feathers());
    app.use('users', service)
      .configure(authentication({ secret: 'supersecret' }));

    options = app.get('authentication');
    options.name = 'cas';

    verifier = new Verifier(app, options);
  });

  it('is CommonJS compatible', () => {
    expect(typeof require('../lib/verifier')).to.equal('function');
  });

  it('exposes the Verifier class', () => {
    expect(typeof Verifier).to.equal('function');
  });

  describe('constructor', () => {
    it('retains an app reference', () => {
      expect(verifier.app).to.deep.equal(app);
    });

    it('sets options', () => {
      expect(verifier.options).to.deep.equal(options);
    });

    it('sets service using service path', () => {
      expect(verifier.service).to.deep.equal(app.service('users'));
    });

    it('sets a passed in service instance', () => {
      options.service = service;
      expect(new Verifier(app, options).service).to.deep.equal(service);
    });

    describe('when service is undefined', () => {
      it('throws an error', () => {
        expect(() => {
          new Verifier(app, {}); // eslint-disable-line
        }).to.throw();
      });
    });
  });

  describe('_normalizeResult', () => {
    describe('when has results', () => {
      it('returns entity when paginated', () => {
        return verifier._normalizeResult({ data: [user] }).then(result => {
          expect(result).to.deep.equal(user);
        });
      });

      it('returns entity when not paginated', () => {
        return verifier._normalizeResult([user]).then(result => {
          expect(result).to.deep.equal(user);
        });
      });

      it('calls toObject on entity when present', () => {
        user.toObject = sinon.spy();
        return verifier._normalizeResult({ data: [user] }).then(() => {
          expect(user.toObject).to.have.been.calledOnce;
        });
      });

      it('calls toJSON on entity when present', () => {
        user.toJSON = sinon.spy();
        return verifier._normalizeResult({ data: [user] }).then(() => {
          expect(user.toJSON).to.have.been.calledOnce;
        });
      });
    });

    describe('when no results', () => {
      it('rejects with false when paginated', () => {
        return verifier._normalizeResult({ data: [] }).catch(error => {
          expect(error).to.equal(false);
        });
      });

      it('rejects with false when not paginated', () => {
        return verifier._normalizeResult([]).catch(error => {
          expect(error).to.equal(false);
        });
      });
    });
  });

  describe('verify', () => {
    it('calls find on the provided service', done => {
      verifier.verify({}, 'test.user', () => {
        const query = { user: 'test.user', $limit: 1 };
        expect(service.find).to.have.been.calledOnce;
        expect(service.find).to.have.been.calledWith({ query });
        done();
      });
    });

    it('calls _normalizeResult', done => {
      sinon.spy(verifier, '_normalizeResult');
      verifier.verify({}, 'test.user', () => {
        expect(verifier._normalizeResult).to.have.been.calledOnce;
        verifier._normalizeResult.restore();
        done();
      });
    });

    it('returns the entity', done => {
      verifier.verify({}, 'test.user', (error, entity) => {
        expect(error).to.equal(null);
        expect(entity).to.deep.equal(profile);
        done();
      });
    });

    it('returns errors', done => {
      const authError = new Error('An error');
      verifier._normalizeResult = () => Promise.reject(authError);
      verifier.verify({}, 'test.user', (error, entity) => {
        expect(error).to.equal(authError);
        expect(entity).to.equal(undefined);
        done();
      });
    });
  });
});
