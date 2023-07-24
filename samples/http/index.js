/* A simple sample demonstrating OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2023 by Håvard Stranden and contributions by Albin Hedwall
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 */

const { RelyingParty, extensions} = require('openid');

const PORT = 4004;
const BASE_URL = 'https://example.com'; // The "base url" of your website

const extensionList = [
  new extensions.UserInterface(),
  new extensions.SimpleRegistration({
    "nickname": true,
    "email": true,
    "fullname": true,
    "dob": true,
    "gender": true,
    "postcode": true,
    "country": true,
    "language": true,
    "timezone": true
  }),
  new extensions.AttributeExchange({
    "http://axschema.org/contact/email": "required",
    "http://axschema.org/namePerson/friendly": "required",
    "http://axschema.org/namePerson": "required"
  }),
  new extensions.PAPE({
    "max_auth_age": 24 * 60 * 60, // one day
    "preferred_auth_policies": "none" //no auth method preferred.
  })
];

const relyingParty = new RelyingParty(
  BASE_URL + '/verify', // Verification URL (yours)
  null, // Realm (optional, specifies realm for OpenID authentication)
  false, // Use stateless verification
  false, // Strict mode
  extensionList); // List of extensions to enable and include


let server = require('http').createServer(async (req, res) => {
  let parsedUrl = new URL(req.url, BASE_URL)
  if (parsedUrl.pathname == '/authenticate') {
    // User supplied identifier
    const identifier = parsedUrl.searchParams.get('openid_identifier');

    // Resolve identifier, associate, and build authentication URL
    const authUrl = await relyingParty.authenticate(identifier, false).catch((error) => {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Authentication failed: ' + error.message);
    });

    if (!authUrl) {
      return;
    } else {
      res.writeHead(302, { Location: authUrl });
      res.end();
    }
  } else if (parsedUrl.pathname == '/verify') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });

    // Verify identity assertion
    // NOTE: Passing just the URL is also possible
    const result = await relyingParty.verifyAssertion(parsedUrl).catch((error) => {
      res.end('Authentication failed: ' + error.message);
    });

    // Result contains properties:
    // - authenticated (true/false)
    // - answers from any extensions (e.g. 
    //   "http://axschema.org/contact/email" if requested 
    //   and present at provider)
    res.end((result.authenticated ? 'Success :)' : 'Failure :(') +
      '\n\n' + JSON.stringify(result));
  } else {
    // Deliver an OpenID form on all other URLs
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!DOCTYPE html><html><body>'
      + '<form method="get" action="/authenticate">'
      + '<p>Login using OpenID</p>'
      + '<input name="openid_identifier" />'
      + '<input type="submit" value="Login" />'
      + '</form></body></html>');
  }
});

server.listen(PORT, () => {
  console.log('Listening on port ' + PORT)
});