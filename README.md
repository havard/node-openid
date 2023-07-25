# OpenID for Node.js

OpenID for Node.js is (yes, you guessed it) an OpenID implementation for Node.js. 

Highlights and features include:

- Full OpenID 1.0/1.1/2.0 compliant Relying Party (client) implementation
- Easy to use API
- Simple extension points for association state
- Safety checks for which providers to use

<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->
## Table of content
- [Download](#download)
- [Installation](#installation)
- [Examples](#examples)
- [API  ](#api)
  * [RelyingParty  ](#relyingparty)
    + [Methods](#methods)
      - [authenticate()](#authenticate)
      - [verifyAssertion()](#verifyassertion)
  * [Extension](#extension)
  * [extensions](#extensions)
- [Types](#types)
  * [ValidityChecks](#validitychecks)
  * [AssertionResponse](#assertionresponse)
  * [ErrorMessage](#errormessage)
- [Supported Extensions](#supported-extensions)
- [License](#license)

<!-- TOC end -->

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
```js
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
```js
{
  authenticated: boolean,
  claimedIdentifier: string | null

  + VALUES ADDED BY EXTENSIONS
}
```
### ErrorMessage
```js
{
  message: string
}
```
## Supported Extensions
This library comes with built-in support for the following OpenID extensions:

 - The Simple Registration (SREG) 1.1 extension is implemented as `extensions.SimpleRegistration`.
 - The Attribute Exchange (AX) 1.0 extension is implemented as `extensions.AttributeExchange`.
 - The OAuth 1.0 extension is implemented as `extensions.OAuthHybrid`.
 - The User Interface 1.0 extension is implemented as `extensions.UserInterface`.
 - The Provider Authentication Policy Extension 1.0 (PAPE) is implemented as `extensions.pape`.
## License

OpenID for Node.js is licensed under the MIT license. See LICENSE for further details.