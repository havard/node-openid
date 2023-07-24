# OpenID for Node.js

OpenID for Node.js is (yes, you guessed it) an OpenID implementation for Node.js. 

Highlights and features include:

- Full OpenID 1.0/1.1/2.0 compliant Relying Party (client) implementation
- Easy to use API
- Simple extension points for association state
- Safety checks for which providers to use

## Download

The library can be [reviewed and retrieved from GitHub](http://github.com/havard/node-openid).

## Installation

If you use [`npm`](http://npmjs.org):
```sh
npm i openid
```

If you use [`yarn`](https://yarnpkg.com/):
```sh
yarn add openid
```

If you use [`bun`](https://bun.sh/):
```sh
bun add openid
```

The package can then be imported using both commonjs (require) and es6 modules (import).

## Examples

Examples including extensions can be found in the [`samples`](tree/master/samples) folder in the GitHub repository.

## API  
### RelyingParty  
```js
const rp = new RelyingParty(returnUrl, realm, stateless, strict, extensions, validityChecks?)
```
* `returnUrl`: string  
  * The URL to which openid authentication should return to.
* `realm`: string | null  
  * Can be either null or the url of the service that is requesting the user to identify themselves (your website most likely).
* `stateless`: boolean
  * Whether or not to use stateless authentication.
* `strict`: boolean  
  * Whether or not to use strict mode.
* `extensions`: Extension[]  
  * Array of extensions, can be empty.
* `validityChecks`: ValidityChecks
  * Refer to [ValidityChecks](#validitychecks)
#### Methods
##### authenticate()
```js
const authUrl = await rp.authenticate(identifier)
```
* `identifier`: string
  * String identifier in the form of an URL from which the RelyingParty can find an openid provider.
* `returns`: Promise\<string\>  
  * URL that can be used to authenticate a user.
* `throws`: ErrorMessage
  * Refer to [ErrorMessage](#errormessage)
##### verifyAssertion()
```js
const result = await rp.verifyAssertion(url)
```
* `url`: string | URL
  * The url the user was redirected to by the openid provider, including query/search. Can be given as string or URL object.
* `returns`: Promise\<AssertionResponse\>  
  * Refer to [AssertionResponse](#assertionresponse)
* `throws`: ErrorMessage
  * Refer to [ErrorMessage](#errormessage)
### Extension
```js
class MyExtension extends Extension {
  fillResult(params, result) {
    // Add implementation here
  }
}
```
Abstract class that can be implemented to create your own extensions. The only required method is fillResult, but you can also implement your own constructor.

The following properties and methods are available on Extension:
```ts
requestParams: Record<string, string>;

getHeader(header: string): string;

static getExtensionAlias(params: URLSearchParams, ns: string): string;
```
### extensions
```js
{
    AttributeExchange,
    OAuthHybrid,
    PAPE,
    SimpleRegistration,
    UserInterface
}
```
An object containing all built-in extensions.
## Types
### ValidityChecks
```ts
{
    /**
     * Checks if ns is in this array
     */
    ns: string[],
    /**
     * Checks if claimed_id starts with any of these
     */
    claimed_id: string[],
    /**
     * Checks if identity starts with any of these
     */
    identity: string[],
    /**
     * Checks if op_endpoint is in this array
     */
    op_endpoint: string[]
}
```
### AssertionResponse
```ts

```
## Supported Extensions
This library comes with built-in support for the following OpenID extensions:

 - The Simple Registration (SREG) 1.1 extension is implemented as `extensions.SimpleRegistration`.
 - The Attribute Exchange (AX) 1.0 extension is implemented as `extensions.AttributeExchange`.
 - The OAuth 1.0 extension is implemented as `extensions.OAuthHybrid`.
 - The User Interface 1.0 extension is implemented as `extensions.UserInterface`.
 - The Provider Authentication Policy Extension 1.0 (PAPE) is implemented as `extensions.pape`.

## How does it work?  
### Storing association state

To provide a way to save/load association state, you need to mix-in two functions in
the `openid` module:

 - `saveAssociation(provider, type, handle, secret, expiry_time_in_seconds, callback)` is called when a new association is established during authentication. The callback should be called with any error as its first argument (or `null` if no error occured).
 - `loadAssociation(handle, callback)` is used to retrieve the association identified by `handle` when verification happens. The callback should be called with any error as its first argument (and `null` as the second argument), or an object with the keys `provider`, `type`, `secret` if the association was loaded successfully.

The `openid` module includes default implementations for these functions using a simple object to store the associations in-memory.

### Caching discovered information

The verification of a positive assertion (i.e. an authenticated user) can be sped up significantly by avoiding the need for additional provider discoveries when possible. In order to achieve, this speed-up, node-openid needs to cache its discovered providers. You can mix-in two functions to override the default cache, which is an in-memory cache utilizing a simple object store:
  
  - `saveDiscoveredInformation(key, provider, callback)` is used when saving a discovered provider.  The following behavior is required:
    - The `key` parameter should be uses as a key for storing the provider - it will be used as the lookup key when loading the provider. (Currently, the key is either a claimed identifier or an OP-local identifier, depending on the OpenID context.)
    - When saving fails for some reason, `callback(error)` is called with `error` being an error object specifying what failed.
    - When saving succeeds, `callback(null)` is called.

  - `loadDiscoveredInformation(key, callback)` is used to load any previously discovered information about the provider for an identifier. The following behavior is required:    
      - When no provider is found for the identifier, `callback(null, null)` is called (i.e. it is not an error to not have any data to return).
      - When loading fails for some reason, `callback(error, null)` is called with `error` being an error string specifying why loading failed.
      - When loading succeeds, `callback(null, provider)` is called with the exact provider object that was previously stored using `saveDiscoveredInformation`.
  
## License

OpenID for Node.js is licensed under the MIT license. See LICENSE for further details.