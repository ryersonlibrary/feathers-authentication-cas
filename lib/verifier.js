const Debug = require('debug');

const debug = Debug('@rula/feathers-authentication-cas:verify');

class CASVerifier {
  constructor (app, options = {}) {
    this.app = app;
    this.options = options;
    this.propMap = options.propertyMap || {};
    this.service = typeof options.service === 'string' ? app.service(options.service) : options.service;

    if (!this.service) {
      throw new Error(`options.service does not exist for authentication.
        Make sure you are passing a valid service path or instance that is
        initialized before calling @rula/feathers-authentication-cas.`)
    }

    this._normalizeResult = this._normalizeResult.bind(this);
    this.verify = this.verify.bind(this);
  }

  _normalizeResult (results) {
    // Paginated services return the array of results in the data attribute.
    let entities = results.data ? results.data : results;
    let entity = entities[0];

    // Handle entity not found.
    if (!entity) {
      return Promise.resolve(null);
    }

    // Handle updating mongoose models
    if (typeof entity.toObject === 'function') {
      entity = entity.toObject();
    } else if (typeof entity.toJSON === 'function') {
      // Handle updating Sequelize models
      entity = entity.toJSON();
    }

    debug(`${this.options.entity} found`);
    return Promise.resolve(entity);
  }

  verify (req, user, done) {
    debug('Verifying CAS credentials');

    const usernameField = this.options.entity;

    let username = user;
    let attributes = {};

    if (typeof user !== 'string') {
      // In CASv1.0, just the username is passed in as a string.  In later
      // versions, an object is passed in containing the username in the user
      // field and an extra attributes field.
      username = user.user;
      attributes = user.attributes;
    }

    // Generate a query looking for the username.
    const params = Object.assign({
      'query': {
        [usernameField]: username,
        '$limit': 1
      }
    });

    this.service.find(params)
      .then(response => {
        const results = response.data || response;
        if (!results.length) {
          debug(`A record with matrixId of '${username}' did not exist.`);
          throw new Error('CAS signin successfull but user does not have access.');
        }
        return this._normalizeResult(response);
      })
      .then(entity => {
        // Have a normalized entity.  

        const profile = {
          provider: 'CAS',
          [usernameField]: username
        };

        if (attributes) {
          // Copy over attributes using mapped property names if they exist,
          // otherwise keep the property name.
          for (let key in attributes) {
            let mappedKey = this.propMap[key];
            if (mappedKey) {
              profile[mappedKey] = attributes[key];
            } else {
              profile[key] = attributes[key];
            }
            delete attributes[key];
          }
        }

        const payload = {
          [`${this.options.entity}Id`]: entity.id,
        };
        done(null, profile, payload);
      })
      .catch(error => 
        error ? done(error) : done(null, error, { message: 'Invalid login.' }));
  }
}

module.exports = CASVerifier;