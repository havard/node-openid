# OpenID for node.js

OpenID for node.js is (yes, you guessed it) an OpenID implementation for node.js. 

Highlights and features include:

- Full OpenID 1.1/OpenID 2.0 compliant Relying Party (client) implementation
- Very simple API
- Simple extension points for association state

## Download

The library can be [reviewed and retrieved from GitHub](http://github.com/havard/node-openid).

## Installation

If you use [`npm`](http://npmjs.org), simply do `npm install openid`.

If you don't use npm, you should. Alternatively, you can download the library, and move the 
`lib` folder and `openid.js` to where you want them, and then `require('openid')`. 
(Remember to do `require.paths.unshift` on the directory you put the file in unless it's 
already in your `require.paths`.)

## Examples

Instead of walking through step-by-step, here's a very simple server 
using OpenID for node.js for authentication:

    var openid = require('openid');
    var url = require('url');
    var querystring = require('querystring');
    var relyingParty = new openid.RelyingParty(
        'http://example.com/verify', // Verification URL (yours)
        null, // Realm (optional, specifies realm for OpenID authentication)
        false, // Use stateless verification
        false, // Strict mode
        []); // List of extensions to enable and include


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
              relyingParty.authenticate(identifier, false, function(authUrl)
                  {
                    if (!authUrl)
                    {
                      res.writeHead(500);
                      res.end(error);
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
                relyingParty.verifyAssertion(req, function(result)
                {
                  res.writeHead(200);
                  res.end(result.authenticated 
                      ? 'Success :)'
                      : 'Failure :(');
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

A more elaborate example can be found in `sample.js` in the GitHub repository.

## Storing association state

To provide a way to save/load association state, you need to mix-in two functions in
the `openid` module:

 - `saveAssociation(type, handle, secret, expiry_time)` is called when a new association is established during authentication
 - `loadAssociation(handle)` is used to retrieve the association identified by `handle` when verification happens

The `openid` module includes default implementations for these functions using a simple object to store the associations in-memory.



## License

OpenID for node.js is licensed under the MIT license. See LICENSE for further details. 
The libary includes bigint functionality released by Tom Wu under the BSD license, 
and Base64 functions released by Nick Galbreath under the MIT license. Please see 
`lib/bigint.js` and `lib/base64.js` for the details of the licenses for these functions.
