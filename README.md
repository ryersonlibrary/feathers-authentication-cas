> A Central Authentication Service (CAS) strategy for @feathersjs/authentication using Passport.

## Installation

```
npm install @rula/feathers-authentication-cas --save
```

**Note:** This is only compatible with `feathers-authentication^1.x`.

## Example

```js
const feathers = require('@feathersjs/feathers');
const authentication = require('feathers-authentication');
const jwt = require('feathers-authentication-jwt');
const cas = require('@rula/feathers-authentication-cas');

const app = feathers();

//Setup authentication
app.configure(authentication(settings));
app.configure(jwt());
app.configure(cas({
  casUrl: "https://cas.example.com",
  serviceBaseUrl: "http://localhost:8080",
  servicePath: "/login/validate",
  version: "3.0",
  useSAML: false,
  path: "/login",
  failureRedirect: "/login",
  successRedirect: "/",
  propertyMap: {
    isFromNewLogin: "newLogin",
    longTermAuthenticationRequestTokenUsed: "longAuth"
  }
}));
```

Now starting the test server `npm start` and opening a browser to
`localhost:8080/login` should redirect to your CAS login provider. Upon 
successful login, you will be redirected back to `/` while being logged in and
any futher page authentication can be done with the JWT.

## License

Copyright (c) 2018

Licensed under the [MIT license](LICENSE)
