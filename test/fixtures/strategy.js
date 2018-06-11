const passport = require('passport-strategy');
const util = require('util');

function Strategy (options, verify) {
  passport.Strategy.call(this);
  this.name = 'mock';
  this._options = options;
  this._verify = verify;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  const profile = {
    user: 'test.user',
    provider: 'CAS'
  };

  const callback = (error, user, info) => {
    if (error) {
      return this.error(error);
    }

    if (!user) {
      return this.fail(info.challenge, info.status);
    }

    return this.success(user, info);
  };

  this._verify(req, profile, callback);
};

module.exports = Strategy;
