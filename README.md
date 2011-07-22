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
              relyingParty.authenticate(identifier, false, function(error, authUrl)
                  {
                    if (error)
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
                  res.end(!error && result.authenticated 
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

A more elaborate example including utilizing extensions can be found in `sample.js` in the GitHub repository.

## Storing association state

To provide a way to save/load association state, you need to mix-in two functions in
the `openid` module:

 - `saveAssociation(provider, type, handle, secret, expiry_time, callback)` is called when a new association is established during authentication. The callback should be called with any error as its first argument (or `null` if no error occured).
 - `loadAssociation(handle, callback)` is used to retrieve the association identified by `handle` when verification happens. The callback should be called with any error as its first argument (and `null` as the second argument), or an object with the keys `provider`, `type`, `secret` if the association was loaded successfully.

The `openid` module includes default implementations for these functions using a simple object to store the associations in-memory.

## Caching discovered information

The verification of a positive assertion (i.e. an authenticated user) can be sped up significantly by avoiding the need for additional provider discoveries when possible. In order to achieve, this speed-up, node-openid needs to cache its discovered providers. You can mix-in two functions to override the default cache, which is an in-memory cache utilizing a simple object store:
  
  - `saveDiscoveredInformation(provider, callback)` is used when saving a discovered provider. The `provider.claimedIdentifier` attribute is the key for this object, and will be used for lookup later, when attempting to reuse this discovered information through `loadDiscoveredInformation`. The following behavior is required:
    
    - When saving fails for some reason, `callback(error)` is called with `error` being an error string specifying what failed.
    - When saving succeeds, `callback(null)` is called.

  - `loadDiscoveredInformation(claimedIdentifier, callback)` is used to load any previously discovered information about the provider for a claimed identifier. The following behavior is required:
      
      - When no provider is found for the claimed identifier, `callback(null, null)` is called (i.e. it is not an error to not have any data to return).
      - When loading fails for some reason, `callback(error, null)` is called with `error` being an error string specifying why loading failed.
      - When loading succeeds, `callback(null, provider)` is called with the exact provider object that was previously stored using `saveDiscoveredInformation`.

## License

OpenID for node.js is licensed under the MIT license. See LICENSE for further details. 
The libary includes bigint functionality released by Tom Wu under the BSD license, 
and Base64 functions released by Nick Galbreath under the MIT license. Please see 
`lib/bigint.js` and `lib/base64.js` for the details of the licenses for these functions.
