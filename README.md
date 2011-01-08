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

Download, move `lib` folder and `openid.js` to where you want them, and
`require('openid')`. (Remember to do `require.paths.unshift` on the directory
you put the file in unless it's already in your `require.paths`.)

## Examples

Instead of walking through step-by-step, here's a very simple server 
using OpenID for node.js for authentication:

    var openid = require('openid');
    var url = require('url');
    var server = require('http').createServer(
        function(req, res)
        {
            var parsedUrl = url.parse(req.url, true);
            if(parsedUrl.pathname == '/verify')
            {
                // Verify identity assertion
                var result = openid.verifyAssertion(req); // or req.url
                res.writeHead(200);
                res.end(result.authenticated ? 'Success :)' : 'Failure :(');
            }
            else if(parsedUrl.pathname == '/authenticate')
            {
                // Resolve identifier, associate, build authentication URL
                openid.authenticate(
                    parsedUrl.query.openid_identifier, // user supplied identifier
                    'http://example.com/verify', // our callback URL
                    null, // realm (optional)
                    false, // attempt immediate authentication first?
                    function(authUrl)
                    {
                        res.writeHead(302, { Location: authUrl });
                        res.end();
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
