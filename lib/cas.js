/**
 * Passport authentication strategy using CAS. Based on:
 * https://github.com/sadne/passport-cas
 */
const url = require('url');
const https = require('https');
const parseXml = require('xml2js').parseString;
const processXml = require('xml2js/lib/processors');
const strategy = require('passport-strategy');
const uuid = require('node-uuid');

/**
 * Defines an authentication strategy that communicates with a Central
 * Authentication Service (CAS) server in order to provide single sign on
 * functionality.
 * 
 * @param {Object} options An object with configuration options.
 * @param {Function} verify A function called to verify the returned user.
 */
function CasStrategy(options, verify) {
  if (!verify) {
    throw new Error('CasStrategy requires a verify function.');
  }

  if (!options.casUrl) {
    throw new Error('CasStrategy requires a CAS url to be specified.');
  }

  strategy.call(this);

  this._verify = verify;
  this._casBaseUrl = options.casUrl;
  this._casParsedUrl = url.parse(this._casBaseUrl);
  this._version = options.version || '3.0';
  this._casPropertyMap = options.propertyMap || {};
  this._passReqToCallback = options.passReqToCallback !== false;
  this._useSaml = options.useSaml !== true;

  this._serviceBaseUrl = options.serviceBaseUrl;
  this._servicePath = options.servicePath;
  
  this.name = 'cas';

  let xmlParseOpts = {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [ processXml.stripPrefix, processXml.firstCharLowerCase ],
    attrNameProcessors: [ processXml.firstCharLowerCase ],
    attrValueProcessors: [ processXml.normalize ]
  };

  // Setup validate URI and validate function depending on version and SAML use.
  switch (this._version) {
  case '1.0':
    this._validateUri = '/validate';
    this._validate = (req, body, verified) => {
      const lines = body.split('\n');

      if (lines.length >= 1) {

        if (lines[0] === 'no') {
          return verified(new Error('CAS authentication failed.'));
        } else if (lines[0] === 'yes' && lines.length >= 2) {
          if (this._passReqToCallback) {
            this._verify(req, lines[1], verified);
          } else {
            this._verify(lines[1], verified);
          }
          return;
        }
      }

      return verified(new Error('Malformed server response.'));
    };
    break;
  case '2.0':
  case '3.0':
    if (this._useSaml) {
      this._validateUri = '/samlValidate';
      this._validate = (req, body, verified) => {
        parseXml(body, xmlParseOpts, (err, result) => {
          if (err) {
            return verified(new Error('Unable to parse response from server.'));
          }

          try {
            const status = result.envelope.body.response.status.statusCode;
            const content = result.envelope.body.response.assertion;

            if (status.$.value.indexOf('success') > -1) {
              let attributes = {};
              const casAttrs = content.attributeStatement.attribute;

              if (casAttrs.length && casAttrs.length > 1) {
                for (let i = 0, len = casAttrs.length; i < len; i++) {
                  let ca = casAttrs[i];
                  attributes[ca.$.attributeName] = ca.attributeValue;
                }
              } else {
                attributes[casAttrs.$.attributeName] = casAttrs.attributeValue;
              }

              const profile = {
                user: content.authenticationStatement.subject.nameIdentifier,
                attributes: attributes
              };

              if (this._passReqToCallback) {
                this._verify(req, profile, verified);
              } else {
                this._verify(profile, verified);
              }

              return;
            }

            return verified(new Error('CAS server returned neither success or fail.'));
          } catch (e) {
            return verified(new Error('CAS authentication encountered an error. ' + e));
          }
        });
      };
    } else {
      this._validateUri = this._version === '3.0' ? '/p3/serviceValidate' : '/serviceValidate';
      this._validate = (req, body, verified) => {
        parseXml(body, xmlParseOpts, (err, result) => {
          if (err) {
            return verified(new Error('Unable to parse response from server.'));
          }

          try {
            const response = result.serviceResponse;

            if (response.authenticationFailure) {
              const c = response.authenticationFailure.$.code;
              return verified(new Error(`CAS authentication failed with: ${c}`));
            }

            // Anything other than failure should be success.
            const success = response.authenticationSuccess;

            if (success) {
              if (this._passReqToCallback) {
                this._verify(req, success, verified);
              } else {
                this._verify(success, verified);
              }

              return;
            }

            return verified(new Error('CAS server returned neither success or fail.'));
          } catch (e) {
            return verified(new Error('CAS authentication encountered an error. ' + e));
          }
        });
      };
    }
    break;
  default:
    throw new Error('Unsupported CAS version ' + this._version);
  }
}

CasStrategy.prototype.service = function (req) {
  const servicePath = this._servicePath || req.originalUrl;
  const resolvedUrl = url.resolve(this._serviceBaseUrl, servicePath);
  const parsedUrl = url.parse(resolvedUrl, true);

  delete parsedUrl.query.ticket;
  delete parsedUrl.search;

  return url.format(parsedUrl);
};

CasStrategy.prototype.authenticate = function (req, options) {
  options = options || {};

  const service = this.service(req);
  const ticket = req.query['ticket'];

  if (!ticket) {
    // If no ticket is found on the request, the client needs to be redirected
    // to the CAS server to enter login credentials.

    const redirectUrl = url.parse(this._casBaseUrl + '/login', true);

    redirectUrl.query.service = service;

    if (options.loginRenew) {
      redirectUrl.query.renew = 'true';
    }

    if (options.loginGateway && !options.loginRenew) {
      redirectUrl.query.gateway = 'true';
    }

    if (options.loginMethod && (options.loginMethod === 'GET' ||
        options.loginMethod === 'POST') && this._version === '3.0') {
      redirectUrl.query.method = options.loginMethod;
    }
  
    // Redirect to the CAS login Url.
    return this.redirect(url.format(redirectUrl));
  }

  // Build the SOAP envelope for use with a SAML request.
  const soapEnvelope = 
  `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
      <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
          MajorVersion="1" MinorVersion="1" RequestID="${uuid.v4()}"
          IssueInstant="${new Date().toISOString()}">
        <samlp:AssertionArtifact>${ticket}</samlp:AssertionArtifact>
    </samlp:Request>
    </SOAP-ENV:Body>
  </SOAP-ENV:Envelope>`;

  // Set the request options.
  const reqOptions = {
    host: this._casParsedUrl.hostname,
    port: this._casParsedUrl.port,
    method: this._useSaml ? 'POST' : 'GET',
    path: url.format({
      pathname: this._casParsedUrl.pathname + this._validateUri,
      query: this._useSaml ? { TARGET: service } : { ticket: ticket, service: service }
    })
  };

  // Create the request.
  const request = https.request(reqOptions, response => {
    // Handle request response.
    response.setEncoding('utf8');
    let data = '';

    response.on('data', chunk => {
      return data += chunk;
    });

    // When the response is finished, validate it.
    return response.on('end', () => {
      return this._validate(req, data, (err, user, info) => {
        if (err) {
          return this.error(err);
        }

        if (!user) {
          return this.fail(info);
        }

        this.success(user, info);
      });
    });
  });

  request.on('error', err => {
    return this.fail(new Error(err));
  });

  if (this._useSaml) {
    request.write(soapEnvelope);
    request.end();
  }
};

/**
 * Expose `CasStrategy` as `Strategy`.
 */
module.exports.Strategy = CasStrategy;
