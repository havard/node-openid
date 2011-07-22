/* A simple sample demonstrating OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
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

var openid = require('./openid');
var url = require('url');
var querystring = require('querystring');

var extensions = [new openid.UserInterface(), 
                  new openid.SimpleRegistration(
                      {
                        "nickname" : true, 
                        "email" : true, 
                        "fullname" : true,
                        "dob" : true, 
                        "gender" : true, 
                        "postcode" : true,
                        "country" : true, 
                        "language" : true, 
                        "timezone" : true
                      }),
                  new openid.AttributeExchange(
                      {
                        "http://axschema.org/contact/email": "required",
                        "http://axschema.org/namePerson/friendly": "required",
                        "http://axschema.org/namePerson": "required"
                      })];

var relyingParty = new openid.RelyingParty(
    'http://example.com/verify', // Verification URL (yours)
    null, // Realm (optional, specifies realm for OpenID authentication)
    false, // Use stateless verification
    false, // Strict mode
    extensions); // List of extensions to enable and include


var server = require('http').createServer(
    function(req, res)
    {
        var parsedUrl = url.parse(req.url);
        if(parsedUrl.pathname == '/authenticate')
        { 
          // User supplied identifier
          var query = querystring.parse(parsedUrl.query);
          var identifier = query.openid_identifier;

          // Resolve identifier, associate, and build authentication URL
          relyingParty.authenticate(identifier, false, function(error, authUrl)
          {
            if(error)
            {
              res.writeHead(200);
              res.end('Authentication failed: ' + error);
            }
            else if (!authUrl)
            {
              res.writeHead(200);
              res.end('Authentication failed');
            }
            else
            {
              res.writeHead(302, { Location: authUrl });
              res.end();
            }
          });
        }
        else if(parsedUrl.pathname == '/verify')
        {
          // Verify identity assertion
          // NOTE: Passing just the URL is also possible
          relyingParty.verifyAssertion(req, function(error, result)
          {
            res.writeHead(200);

            if(error)
            {
              res.end('Authentication failed: ' + error);
            }
            else
            {
              // Result contains properties:
              // - authenticated (true/false)
              // - answers from any extensions (e.g. 
              //   "http://axschema.org/contact/email" if requested 
              //   and present at provider)
              res.end((result.authenticated ? 'Success :)' : 'Failure :(') +
                '\n\n' + JSON.stringify(result));
            }
          });
        }
        else
        {
            // Deliver an OpenID form on all other URLs
            res.writeHead(200);
            res.end('<!DOCTYPE html><html><body>'
                + '<form method="get" action="/authenticate">'
                + '<p>Login using OpenID</p>'
                + '<input name="openid_identifier" />'
                + '<input type="submit" value="Login" />'
                + '</form></body></html>');
        }
    });
server.listen(80);
