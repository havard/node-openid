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

require.paths.unshift(__dirname);

var openid = require('openid');
var url = require('url');
var querystring = require('querystring');
var server = require('http').createServer(
    function(req, res)
    {
        var parsedUrl = url.parse(req.url);
        if(parsedUrl.pathname == '/verify')
        {
            // Verify identity assertion
            var result = openid.verifyAssertion(req); // or req.url
            var attributes = [];
            var sreg = new openid.SimpleRegistration(result);
            for (var k in sreg)
              attributes.push(k + ": " + sreg[k]);
            var ax = new openid.AttributeExchange(result);
            for (var k in ax)
              attributes.push(k + ": " + ax[k]);
            res.writeHead(200);
            res.end(result.authenticated ? 'Success :)\n' + attributes.join("\n") : 'Failure :(\n' + result.error);
        }
        else if(parsedUrl.pathname == '/authenticate')
        {
            // Resolve identifier, associate, build authentication URL
            openid.authenticate(
                querystring.parse(parsedUrl.query).openid_identifier, // user supplied identifier
                'http://example.com/verify', // our callback URL
                null, // realm (optional)
                false, // attempt immediate authentication first?
                function(authUrl)
                {
                    res.writeHead(302, { Location: authUrl });
                    res.end();
                }, [new openid.UserInterface(), new openid.SimpleRegistration({
                  "nickname" : true, "email" : true, "fullname" : true,
                  "dob" : true, "gender" : true, "postcode" : true,
                  "country" : true, "language" : true, "timezone" : true}),
                  new openid.AttributeExchange({
                  "http://axschema.org/contact/email": "required",
                  "http://axschema.org/namePerson/friendly": "required",
                  "http://axschema.org/namePerson": "required"})]);
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
