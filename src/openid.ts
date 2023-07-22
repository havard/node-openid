/* OpenID for node.js
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
 *
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */

import crypto from 'crypto';
import { get, post } from './http';
import xrds from './lib/xrds';
import Extension from 'extensions';

interface Association {
  provider: Provider,
  type: string,
  secret: string
}

let AX_MAX_VALUES_COUNT = 1000;

let openid = exports;

function hasOwnProperty(obj: any, key: string) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

interface ErrorMessage {
  message: string;
}

export type AssertionResponse = {
  authenticated: false;
} | {
  authenticated: true;
  claimedIdentifier: string | null;
}

type Realm = string | null;

interface Provider {
  endpoint: string;
  claimedIdentifier?: string;
  version: string;
  localIdentifier: string | null;
}

export interface Request {
  method: string;
  url: string;
  getHeader(header: string): string | number | string[] | undefined;
  on(event: string, cb: (data: any) => void): void;
}

export const isRequest = (b: any): b is Request => {
  return (b as Request).method !== undefined &&
    (b as Request).url !== undefined &&
    typeof (b as Request).getHeader === 'function'
    && typeof (b as Request).on === 'function';
}

function isValidDate(d: any) {
  return d instanceof Date && !isNaN(d as unknown as number);
}

type RequestOrUrl = Request | URL | string;

export class RelyingParty {
  returnUrl: string;
  realm: Realm;
  stateless: boolean;
  strict: boolean;
  extensions: Extension[];

  #associations: Record<string, Association> = {};
  #discoveries: Record<string, Provider> = {};
  #nonces: Record<string, Date> = {};

  constructor(returnUrl: string, realm: Realm, stateless: boolean, strict: boolean, extensions: Extension[]) {
    this.returnUrl = returnUrl;
    this.realm = realm || null;
    this.stateless = stateless;
    this.strict = strict;
    this.extensions = extensions;
  }

  authenticate(identifier: string, immediate: boolean) {
    return this.#authenticate(identifier, this.returnUrl, this.realm, immediate, this.stateless, this.extensions, this.strict);
  }

  verifyAssertion(requestOrUrl: RequestOrUrl) {
    return this.#verifyAssertion(requestOrUrl, this.returnUrl, this.stateless, this.extensions, this.strict);
  }

  async #authenticate(identifier: string, returnUrl: string, realm: Realm, immediate: boolean, stateless: boolean, extensions: Extension[], strict: boolean) {
    return new Promise<string>(async (resolve, reject) => {
      const providers = await this.#discover(identifier, strict);
      if (!providers || providers.length === 0) {
        return reject({ message: 'No providers found for the given identifier' });
      }

      let providerIndex = -1;

      let rp = this;

      (async function chooseProvider(error?: ErrorMessage, authUrl?: string) {
        if (!error && authUrl) {
          let provider = providers[providerIndex];

          if (provider.claimedIdentifier) {
            let useLocalIdentifierAsKey = !provider.version.includes('2.0') && provider.localIdentifier && provider.claimedIdentifier != provider.localIdentifier;

            rp.#saveDiscoveredInformation((useLocalIdentifierAsKey ? provider.localIdentifier : provider.claimedIdentifier) ?? '', provider)
            return resolve(authUrl);
          } else if (provider.version.includes('2.0')) {
            return resolve(authUrl);
          } else {
            chooseProvider({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' });
          }
        }

        if (++providerIndex >= providers.length) {
          return reject({ message: 'No usable providers found for the given identifier' });
        }

        let currentProvider = providers[providerIndex];
        if (stateless) {
          const url = await requestAuthentication(currentProvider, null, returnUrl, realm, immediate, extensions).catch(chooseProvider);

          if (!url) {
            return;
          }

          return chooseProvider(undefined, url);
        }

        const answer = await rp.#associate(currentProvider, strict).catch(chooseProvider);

        if (!answer) {
          return;
        }

        if (answer.error) {
          return chooseProvider(error || {
            message: answer.error
          });
        }

        const url = await requestAuthentication(currentProvider, answer.assoc_handle, returnUrl,
          realm, immediate, extensions || {}).catch(chooseProvider);

        if (url) {
          chooseProvider(undefined, url);
        }
      })();
    })
  }

  async #verifyAssertion(requestOrUrl: RequestOrUrl, originalReturnUrl: string, stateless: boolean, extensions: Extension[] = [], strict: boolean): Promise<{ authenticated: boolean }> {
    return new Promise(async (resolve, reject) => {
      if (isRequest(requestOrUrl)) {
        if (requestOrUrl.method.toUpperCase() == 'POST') {
          if ((requestOrUrl.getHeader('content-type')?.toString() || '').toLowerCase().indexOf('application/x-www-form-urlencoded') === 0) {
            // POST response received
            let data = '';

            requestOrUrl.on('data', (chunk) => {
              data += chunk;
            });

            requestOrUrl.on('end', () => {
              let params = (new URLSearchParams(data));
              return resolve(this.#verifyAssertionData(params, stateless, extensions, strict));
            });
          } else {
            return reject({ message: 'Invalid POST response from OpenID provider' });
          }

          return;
        } else if (requestOrUrl.method.toUpperCase() !== 'GET') {
          return reject({ message: 'Invalid request method from OpenID provider' });
        }
      }

      let assertionUrl: URL;
      if (isRequest(requestOrUrl)) {
        assertionUrl = new URL(requestOrUrl.url);
      } else {
        assertionUrl = requestOrUrl instanceof URL ? requestOrUrl : new URL(requestOrUrl);
      }

      if (!this.#verifyReturnUrl(assertionUrl, new URL(originalReturnUrl))) {
        return reject({ message: 'Invalid return URL' });
      }

      resolve(await this.#verifyAssertionData(assertionUrl.searchParams, stateless, extensions, strict));
    })
  }

  async #discover(abnormalIdentifier: string, strict: boolean): Promise<Provider[]> {
    let identifier = normalizeIdentifier(abnormalIdentifier);
    if (!identifier) {
      throw { message: 'Invalid identifier' };
    }

    if (identifier.indexOf('http') !== 0) {
      // XRDS
      identifier = 'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml';
    }

    // Try XRDS/Yadis discovery
    const providers = await resolveXri(identifier).catch(_ => {
      return [] as Provider[];
    });

    if (!providers.length) {
      // Fallback to HTML discovery
      const providers = await resolveHtml(identifier).catch(_ => {
        return [] as Provider[];
      })

      if (!providers.length) {
        const providers = await resolveHostMeta(identifier, strict).catch(_ => {
          return [] as Provider[];
        })

        return providers;
      }

      return providers;
    }
    // Add claimed identifier to providers with local identifiers
    // and OpenID 1.0/1.1 providers to ensure correct resolution 
    // of identities and services
    for (let i = 0, len = providers.length; i < len; ++i) {
      let provider = providers[i];
      if (!provider.claimedIdentifier &&
        (provider.localIdentifier || provider.version.indexOf('2.0') === -1)) {
        provider.claimedIdentifier = identifier;
      }
    }

    return providers;
  }

  async #associate(provider: Provider, strict: boolean, algorithm = 'DH-SHA256'): Promise<Record<string, string>> {
    let params = generateAssociationRequestParameters(provider.version, algorithm);
    if (!algorithm) {
      algorithm = 'DH-SHA256';
    }

    let dh: crypto.DiffieHellman | undefined = undefined;
    if (!algorithm.includes('no-encryption')) {
      dh = createDiffieHellmanKeyExchange(algorithm);
      params['openid.dh_modulus'] = bigIntToBase64(dh.getPrime('binary'));
      params['openid.dh_gen'] = bigIntToBase64(dh.getGenerator('binary'));
      params['openid.dh_consumer_public'] = bigIntToBase64(dh.getPublicKey('binary'));
    }

    const { data: responseData, status } = await post(provider.endpoint, params).catch(_ => {
      throw {
        message: 'HTTP request failed'
      };
    })

    if (status != 200 && status != 400) {
      throw {
        message: 'HTTP request failed'
      };
    }

    let data = decodePostData(responseData);

    if (data.error_code === 'unsupported-type' || !data.ns) {
      if (algorithm === 'DH-SHA1') {
        if (strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
          throw { message: 'Channel is insecure and no encryption method is supported by provider' };
        } else {
          return openid.associate(provider, strict, 'no-encryption-256');
        }
      } else if (algorithm === 'no-encryption-256') {
        if (strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
          throw { message: 'Channel is insecure and no encryption method is supported by provider' }
        }
        /*else if(provider.version.indexOf('2.0') === -1)
        {
          // 2011-07-22: This is an OpenID 1.0/1.1 provider which means
          // HMAC-SHA1 has already been attempted with a blank session
          // type as per the OpenID 1.0/1.1 specification.
          // (See http://openid.net/specs/openid-authentication-1_1.html#mode_associate)
          // However, providers like wordpress.com don't follow the 
          // standard and reject these requests, but accept OpenID 2.0
          // style requests without a session type, so we have to give
          // those a shot as well.
          callback({ message: 'Provider is OpenID 1.0/1.1 and does not support OpenID 1.0/1.1 association.' });
        }*/
        else {
          return this.#associate(provider, strict, 'no-encryption');
        }
      } else if (algorithm === 'DH-SHA256') {
        return this.#associate(provider, strict, 'DH-SHA1');
      }
    }

    if (data.error) {
      throw { message: data.error };
    }

    let hashAlgorithm = algorithm.indexOf('256') !== -1 ? 'sha256' : 'sha1';

    let secret: string;
    if (!dh) {
      secret = data.mac_key;
    } else {
      let serverPublic = bigIntFromBase64(data.dh_server_public);
      let sharedSecret = btwoc(dh.computeSecret(serverPublic, 'binary', 'binary'));
      let hash = crypto.createHash(hashAlgorithm);
      hash.update(Buffer.from(sharedSecret, 'binary'));
      sharedSecret = hash.digest('binary');
      let encMacKey = base64decode(data.enc_mac_key);
      secret = base64encode(xor(encMacKey, sharedSecret));
    }

    if (!data.assoc_handle) {
      throw { message: 'OpenID provider does not seem to support association; you need to use stateless mode' };
    }

    this.#saveAssociation(provider, hashAlgorithm,
      data.assoc_handle, secret, parseInt(data.expires_in));

    return data;
  }

  #verifyReturnUrl(assertionUrl: URL, originalReturnUrl: URL) {
    let receivedReturnUrl = new URL(assertionUrl.searchParams.get('openid.return_to') ?? '');
    if (!receivedReturnUrl) {
      return false;
    }

    if (originalReturnUrl.protocol !== receivedReturnUrl.protocol || // Verify scheme against original return URL
      originalReturnUrl.host !== receivedReturnUrl.host || // Verify authority against original return URL
      originalReturnUrl.pathname !== receivedReturnUrl.pathname) { // Verify path against current request URL
      return false;
    }

    // Any query parameters that are present in the "openid.return_to" URL MUST also be present 
    // with the same values in the URL of the HTTP request the RP received
    for (const param of receivedReturnUrl.searchParams.keys()) {
      if (receivedReturnUrl.searchParams.get(param) !== assertionUrl.searchParams.get(param)) {
        return false;
      }
    }

    return true;
  }

  async #verifyAssertionData(params: URLSearchParams, stateless: boolean, extensions: Extension[], strict: boolean) {
    let assertionError = this.#getAssertionError(params);
    if (assertionError) {
      throw { message: assertionError };
    }

    if (!this.#invalidateAssociationHandleIfRequested(params)) {
      throw { message: 'Unable to invalidate association handle' };
    }

    if (!this.#checkNonce(params)) {
      throw { message: 'Invalid or replayed nonce' };
    }

    return await this.#verifyDiscoveredInformation(params, stateless, extensions, strict);
  };

  async #verifyDiscoveredInformation(params: URLSearchParams, stateless: boolean, extensions: Extension[], strict: boolean): Promise<AssertionResponse> {
    let claimedIdentifier = params.get('openid.claimed_id');
    let useLocalIdentifierAsKey = false;
    if (!claimedIdentifier) {
      if (!params.get('openid.ns')) {
        // OpenID 1.0/1.1 response without a claimed identifier
        // We need to load discovered information using the
        // local identifier
        useLocalIdentifierAsKey = true;
      } else {
        // OpenID 2.0+:
        // If there is no claimed identifier, then the
        // assertion is not about an identity
        return { authenticated: false };
      }
    }

    if (useLocalIdentifierAsKey) {
      claimedIdentifier = params.get('openid.identity');
    }

    if (!claimedIdentifier) {
      throw { message: 'No claimed identifier found.' }
    }

    claimedIdentifier = this.#getCanonicalClaimedIdentifier(claimedIdentifier);

    const provider = this.#loadDiscoveredInformation(claimedIdentifier);

    if (provider) {
      return this.#verifyAssertionAgainstProviders([provider], params, stateless, extensions);
    } else if (useLocalIdentifierAsKey) {
      throw { message: 'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.' };
    }

    const providers = await this.#discover(claimedIdentifier, strict).catch(() => {})

    if (!providers || !providers.length) {
      throw { message: 'No OpenID provider was discovered for the asserted claimed identifier' };
    }

    return await this.#verifyAssertionAgainstProviders(providers, params, stateless, extensions);
  }

  async #verifyAssertionAgainstProviders(providers: Provider[], params: URLSearchParams, stateless: boolean, extensions: Extension[]) {
    for (let provider of providers) {
      if (!!params.get('openid.ns') && (!provider.version || provider.version.indexOf(params.get('openid.ns') ?? 'null') !== 0)) {
        continue;
      }

      if (!!provider.version && provider.version.includes('2.0')) {
        let endpoint = params.get('openid.op_endpoint');
        if (provider.endpoint != endpoint) {
          continue;
        }
        if (provider.claimedIdentifier) {
          let p_claimed_id = params.get('openid.claimed_id');
          if (!p_claimed_id) {
            throw { message: 'Provider has claimedIdentifier but url lacks openid.claimed_id' }
          }

          let claimedIdentifier = this.#getCanonicalClaimedIdentifier(p_claimed_id);
          if (provider.claimedIdentifier != claimedIdentifier) {
            throw { message: 'Claimed identifier in assertion response does not match discovered claimed identifier' };
          }
        }
      }

      if (!!provider.localIdentifier && provider.localIdentifier != params.get('openid.identity')) {
        throw { message: 'Identity in assertion response does not match discovered local identifier' };
      }

      let result = await this.#checkSignature(params, provider, stateless);

      if (extensions && result.authenticated) {
        for (let ext in extensions) {
          if (!hasOwnProperty(extensions, ext)) {
            continue;
          }
          let instance = extensions[ext];
          instance.fillResult(params, result);
        }
      }

      return result;
    }

    throw { message: 'No valid providers were discovered for the asserted claimed identifier' };
  }

  #getAssertionError(params: URLSearchParams): string | null {
    if (!params) {
      return 'Assertion request is malformed';
    } else if (params.get('openid.mode') == 'error') {
      return params.get('openid.error');
    } else if (params.get('openid.mode') == 'cancel') {
      return 'Authentication cancelled';
    }

    return null;
  }

  #invalidateAssociationHandleIfRequested(params: URLSearchParams) {
    if (params.get('is_valid') === 'true' && params.get('openid.invalidate_handle')) {
      if (!openid.removeAssociation(params.get('openid.invalidate_handle'))) {
        return false;
      }
    }

    return true;
  }

  #getCanonicalClaimedIdentifier(claimedIdentifier: string) {
    if (!claimedIdentifier) {
      return claimedIdentifier;
    }

    let index = claimedIdentifier.indexOf('#');
    if (index !== -1) {
      return claimedIdentifier.substring(0, index);
    }

    return claimedIdentifier;
  }

  async #checkSignature(params: URLSearchParams, provider: Provider, stateless: boolean): Promise<AssertionResponse> {
    if (!params.get('openid.signed') ||
      !params.get('openid.sig')) {
      throw { message: 'No signature in response' };
    }

    if (stateless) {
      return await this.#checkSignatureUsingProvider(params, provider);
    } else {
      return this.#checkSignatureUsingAssociation(params);
    }
  }

  #checkSignatureUsingAssociation(params: URLSearchParams) {
    const assocHandle = params.get('openid.assoc_handle');
    if (!assocHandle) {
      throw { message: 'No association handle in provider response. Find out whether the provider supports associations and/or use stateless mode.' };
    }

    const association = this.#loadAssociation(assocHandle);
    if (!association) {
      throw { message: 'Invalid association handle' };
    }
    if (association.provider.version.includes('2.0') && association.provider.endpoint !== params.get('openid.op_endpoint')) {
      throw { message: 'Association handle does not match provided endpoint' };
    }

    const signed = params.get('openid.signed');

    if (!signed) {
      throw { message: 'No signature in response' };
    }

    let message = '';
    let signedParams = signed.split(',');
    for (let i = 0; i < signedParams.length; i++) {
      let param = signedParams[i];
      let value = params.get('openid.' + param);
      if (!value) {
        throw { message: 'At least one parameter referred in signature is not present in response' };
      }
      message += param + ':' + value + '\n';
    }

    let hmac = crypto.createHmac(association.type, Buffer.from(association.secret, 'base64'));
    hmac.update(message, 'utf8');
    let ourSignature = hmac.digest('base64');

    if (ourSignature == params.get('openid.sig')) {
      return {
        authenticated: true,
        claimedIdentifier: association.provider.version.indexOf('2.0') !== -1 ? params.get('openid.claimed_id') : association.provider.claimedIdentifier as string
      };
    } else {
      throw { message: 'Invalid signature' };
    }
  }

  async #checkSignatureUsingProvider(params: URLSearchParams, provider: Provider) {
    let requestParams: Record<string, string> =
    {
      'openid.mode': 'check_authentication'
    };

    params.forEach((value, key) => {
      if (key === 'openid.mode') {
        return;
      }

      requestParams[key] = value;
    })

    const { data: responseData, status } = await post(params.get('openid.ns') ? (params.get('openid.op_endpoint') || provider.endpoint) : provider.endpoint, requestParams);

    if (status !== 200 || responseData == null) {
      throw { message: 'Invalid assertion response from provider' };
    } else {
      let data = decodePostData(responseData);
      if (data['is_valid'] == 'true') {
        return {
          authenticated: true,
          claimedIdentifier: provider.version.indexOf('2.0') !== -1 ? params.get('openid.claimed_id') : params.get('openid.identity')
        };
      } else {
        throw { message: 'Invalid signature' };
      }
    }

  }

  #checkNonce(params: URLSearchParams) {
    if (!params.get('openid.ns')) {
      return true; // OpenID 1.1 has no nonce
    }
    if (!params.get('openid.response_nonce')) {
      return false;
    }

    let nonce = params.get('openid.response_nonce');
    if (!nonce) {
      return false;
    }

    let timestampEnd = nonce.indexOf('Z');
    if (timestampEnd == -1) {
      return false;
    }

    // Check for valid timestamp in nonce
    let timestamp = new Date(Date.parse(nonce.substring(0, timestampEnd + 1)));
    if (!isValidDate(timestamp)) {
      return false;
    }

    // Remove old nonces from our store (nonces that are more skewed than 5 minutes)
    this.#removeOldNonces();

    // Check if nonce is skewed by more than 5 minutes
    if (Math.abs(new Date().getTime() - timestamp.getTime()) > 300000) {
      return false;
    }

    // Check if nonce is replayed
    if (this.#nonces[nonce]) {
      return false;
    }

    // Store the nonce
    this.#nonces[nonce] = timestamp;
    return true;
  }

  #removeOldNonces() {
    for (let nonce in this.#nonces) {
      if (hasOwnProperty(this.#nonces, nonce) && Math.abs(new Date().getTime() - this.#nonces[nonce].getTime()) > 300000) {
        delete this.#nonces[nonce];
      }
    }
  }

  #saveAssociation(provider: Provider, type: string, handle: string, secret: string, expiry_time_in_seconds: number) {
    setTimeout(() => {
      this.#removeAssociation(handle);
    }, expiry_time_in_seconds * 1000);

    this.#associations[handle] = { provider: provider, type: type, secret: secret };
  }

  #loadAssociation(handle: string) {
    return this.#associations[handle] ?? null;
  }

  #removeAssociation(handle: string) {
    delete this.#associations[handle];
  }

  #saveDiscoveredInformation(key: string, provider: Provider) {
    this.#discoveries[key] = provider;
  }

  #loadDiscoveredInformation(key: string,) {
    return this.#discoveries[key] ?? null;
  }
}

function btwoc(i: string) {
  if (i.charCodeAt(0) > 127) {
    return String.fromCharCode(0) + i;
  }
  return i;
}

function unbtwoc(i: string) {
  if (i[0] === String.fromCharCode(0)) {
    return i.substring(1);
  }

  return i;
}

function base64encode(str: string) {
  return Buffer.from(str, 'binary').toString('base64');
};

function base64decode(str: string) {
  return Buffer.from(str, 'base64').toString('binary');
};

function bigIntToBase64(binary: string) {
  return base64encode(btwoc(binary));
}

function bigIntFromBase64(str: string) {
  return unbtwoc(base64decode(str));
}

function xor(a: string, b: string) {
  if (a.length != b.length) {
    throw new Error('Length must match for xor');
  }

  let r = '';
  for (let i = 0; i < a.length; ++i) {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
  }

  return r;
}

function buildUrl(url: string, params?: Record<string, string>): string {
  if (params) {
    const search = (new URLSearchParams(params)).toString();

    return new URL(search, url).toString();
  }

  return url;
}
function decodePostData(data: string) {
  let lines = data.split('\n');
  let result: Record<string, string> = {};
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (line.length > 0 && line[line.length - 1] == '\r') {
      line = line.substring(0, line.length - 1);
    }

    let colonIndex = line.indexOf(':');
    if (colonIndex === -1) {
      continue;
    }

    // Check that this works correctly
    let key = line.substring(0, colonIndex - 1);
    let value = line.substring(colonIndex + 1);
    result[key] = value;
  }

  return result;
}

function normalizeIdentifier(identifier: string) {
  identifier = identifier.replace(/^\s+|\s+$/g, '');
  if (!identifier) {
    return null;
  }

  if (identifier.indexOf('xri://') === 0) {
    identifier = identifier.substring(6);
  }

  if (/^[(=@\+\$!]/.test(identifier)) {
    return identifier;
  }

  if (identifier.indexOf('http') === 0) {
    return identifier;
  }

  return 'http://' + identifier;
}

async function parseXrds(xrdsUrl: string, xrdsData: string) {
  let services = xrds.parse(xrdsData);
  if (services == null) {
    throw null;
  }

  let providers: Provider[] = [];
  for (let i = 0, len = services.length; i < len; ++i) {
    let service = services[i];
    let provider: any = {};

    provider.endpoint = service.uri;
    if (/https?:\/\/xri./.test(xrdsUrl)) {
      provider.claimedIdentifier = service.id;
    }

    if (service.type == 'http://specs.openid.net/auth/2.0/signon') {
      provider.version = 'http://specs.openid.net/auth/2.0';
      provider.localIdentifier = service.id;
    } else if (service.type == 'http://specs.openid.net/auth/2.0/server') {
      provider.version = 'http://specs.openid.net/auth/2.0';
    } else if (service.type == 'http://openid.net/signon/1.0' || service.type == 'http://openid.net/signon/1.1') {
      provider.version = service.type;
      provider.localIdentifier = service.delegate;
    } else {
      continue;
    }

    providers.push(provider as Provider);
  }

  return providers;
}

function matchMetaTag(html: string) {
  let metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/ig.exec(html);
  if (!metaTagMatches || metaTagMatches.length < 2) {
    return null;
  }

  let contentMatches = /content="(.*?)"/ig.exec(metaTagMatches[1]);
  if (!contentMatches || contentMatches.length < 2) {
    return null;
  }

  return contentMatches[1];
}

function matchLinkTag(html: string, rel: string) {
  let providerLinkMatches = new RegExp('<link\\s+.*?rel=["\'][^"\']*?' + rel + '[^"\']*?["\'].*?>', 'ig').exec(html);

  if (!providerLinkMatches || providerLinkMatches.length < 1) {
    return null;
  }

  let href = /href=["'](.*?)["']/ig.exec(providerLinkMatches[0]);

  if (!href || href.length < 2) {
    return null;
  }
  return href[1];
}

async function parseHtml(htmlUrl: string, html: string, hops: number): Promise<Provider[]> {
  let metaUrl = matchMetaTag(html);
  if (metaUrl !== null) {
    return resolveXri(metaUrl, hops + 1);
  }

  let provider = matchLinkTag(html, 'openid2.provider');
  if (provider == null) {
    provider = matchLinkTag(html, 'openid.server');
    if (provider == null) {
      throw null;
    }

    let localId = matchLinkTag(html, 'openid.delegate');
    return [{
      version: 'http://openid.net/signon/1.1',
      endpoint: provider,
      claimedIdentifier: htmlUrl,
      localIdentifier: localId
    }]
  }

  let localId = matchLinkTag(html, 'openid2.local_id');
  return [{
    version: 'http://specs.openid.net/auth/2.0/signon',
    endpoint: provider,
    claimedIdentifier: htmlUrl,
    localIdentifier: localId
  }];
}

async function parseHostMeta(hostMeta: string) {
  let match = /^Link: <([^\n\r]+?)>;/.exec(hostMeta);
  if (match != null && match.length > 0) {
    const xriUrl = match[1];
    const providers = await resolveXri(xriUrl).catch(_ => {
      throw null;
    });

    return providers;
  } else {
    throw null;
  }
}

async function resolveXri(xriUrl: string, hops = 1) {
  return new Promise<Provider[]>(async (resolve, reject) => {
    if (hops >= 5) {
      return reject(null);
    }

    const { data, headers, status } = await get(xriUrl).catch(_ => {
      throw null;
    });

    if (status != 200) {
      return reject(null);
    }

    let xrdsLocation = headers['x-xrds-location'];
    if (xrdsLocation) {
      const { data, status } = await get(xrdsLocation).catch(_ => {
        throw null;
      });

      if (status !== 200) {
        return reject(null);
      }

      const providers = await parseXrds(xrdsLocation, data).catch(() => {
        throw null;
      });

      return resolve(providers);
    } else if (data != null) {
      let contentType = headers['content-type'];
      // text/xml is not compliant, but some hosting providers refuse header
      // changes, so text/xml is encountered
      if (contentType && (contentType.indexOf('application/xrds+xml') === 0 || contentType.indexOf('text/xml') === 0)) {
        const providers = await parseXrds(xriUrl, data).catch(() => {
          throw null;
        })

        return resolve(providers);
      }

      const providers = await resolveHtml(xriUrl, hops + 1, data).catch(_ => {
        throw null;
      })

      return resolve(providers);
    }
  })
}

function resolveHtml(identifier: string, hops = 1, data?: any) {
  return new Promise<Provider[]>(async (resolve, reject) => {
    if (hops >= 5) {
      return reject(null);
    }

    if (data == null) {
      const { data, status } = await get(identifier).catch(_ => {
        throw null;
      })

      if (status != 200 || data == null) {
        reject(null);
      }

      const providers = await parseHtml(identifier, data, hops + 1).catch(_ => {
        throw null;
      })

      return resolve(providers);
    }

    const providers = await parseHtml(identifier, data, hops).catch(_ => {
      throw null;
    })

    return resolve(providers);
  })
}

async function resolveHostMeta(identifier: string, strict: boolean, fallBackToProxy = false): Promise<Provider[]> {
  return new Promise<Provider[]>(async (resolve, reject) => {
    let host = new URL(identifier);
    let hostMetaUrl;
    if (fallBackToProxy && !strict) {
      hostMetaUrl = 'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host;
    } else {
      hostMetaUrl = host.protocol + '//' + host.host + '/.well-known/host-meta';
    }

    if (!hostMetaUrl) {
      return reject(null);
    } else {
      const { data, status } = await get(hostMetaUrl).catch(_ => {
        throw null;
      });

      if (status != 200) {
        if (!fallBackToProxy && !strict) {
          const providers = await resolveHostMeta(identifier, strict, true).catch(_ => {
            throw null;
          });

          return resolve(providers);
        }

        return reject(null);
      } else {
        // Attempt to parse the data but if this fails it may be because
        // the response to hostMetaUrl was some other http/html resource.
        // Therefore fallback to the proxy if no providers are found.
        const providers = await parseHostMeta(data).catch(_ => {
          throw null;
        });

        if (providers.length == 0 && !fallBackToProxy && !strict) {
          const providers = await resolveHostMeta(identifier, strict, true).catch(_ => {
            throw null;
          })

          return resolve(providers);
        } else {
          return resolve(providers);
        }
      }
    }
  })
}

openid.discover = async function (abnormalIdentifier: string, strict: boolean): Promise<Provider[]> {
  return new Promise(async (resolve, reject) => {
    let identifier = normalizeIdentifier(abnormalIdentifier);
    if (!identifier) {
      return reject({ message: 'Invalid identifier' });
    }

    if (identifier.indexOf('http') !== 0) {
      // XRDS
      identifier = 'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml';
    }

    // Try XRDS/Yadis discovery
    const providers = await resolveXri(identifier).catch(_ => {
      return [] as Provider[];
    });

    if (!providers.length) {
      // Fallback to HTML discovery
      const providers = await resolveHtml(identifier).catch(_ => {
        return [] as Provider[];
      })

      if (!providers.length) {
        const providers = await resolveHostMeta(identifier, strict).catch(_ => {
          return [] as Provider[];
        })

        return providers;
      }

      return providers;
    }
    // Add claimed identifier to providers with local identifiers
    // and OpenID 1.0/1.1 providers to ensure correct resolution 
    // of identities and services
    for (let i = 0, len = providers.length; i < len; ++i) {
      let provider = providers[i];
      if (!provider.claimedIdentifier &&
        (provider.localIdentifier || provider.version.indexOf('2.0') === -1)) {
        provider.claimedIdentifier = identifier;
      }
    }

    return providers;
  })
}

function createDiffieHellmanKeyExchange(algorithm?: string) {
  let defaultPrime = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr';

  let dh = crypto.createDiffieHellman(defaultPrime, 'base64');

  dh.generateKeys();

  return dh;
}

function generateAssociationRequestParameters(version: string, algorithm: string) {
  let params: Record<string, string> = {
    'openid.mode': 'associate',
  };

  if (version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
  }

  if (algorithm === 'DH-SHA1') {
    params['openid.assoc_type'] = 'HMAC-SHA1';
    params['openid.session_type'] = 'DH-SHA1';
  } else if (algorithm === 'no-encryption-256') {
    if (version.indexOf('2.0') === -1) {
      params['openid.session_type'] = ''; // OpenID 1.0/1.1 requires blank
      params['openid.assoc_type'] = 'HMAC-SHA1';
    } else {
      params['openid.session_type'] = 'no-encryption';
      params['openid.assoc_type'] = 'HMAC-SHA256';
    }
  } else if (algorithm == 'no-encryption') {
    if (version.indexOf('2.0') !== -1) {
      params['openid.session_type'] = 'no-encryption';
    }
    params['openid.assoc_type'] = 'HMAC-SHA1';
  } else {
    params['openid.assoc_type'] = 'HMAC-SHA256';
    params['openid.session_type'] = 'DH-SHA256';
  }

  return params;
}

function requestAuthentication(provider: Provider, assoc_handle: string | null, returnUrl: string, realm: Realm, immediate: Boolean, extensions: Extension[]) {
  return new Promise<string>((resolve, reject) => {
    let params: Record<string, string> = {
      'openid.mode': immediate ? 'checkid_immediate' : 'checkid_setup'
    };

    if (provider.version.indexOf('2.0') !== -1) {
      params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
    }

    for (let extension of extensions) {
      for (let key in extension.requestParams) {
        if (!hasOwnProperty(extension.requestParams, key)) {
          continue;
        }

        params[key] = extension.requestParams[key];
      }
    }

    if (provider.claimedIdentifier) {
      params['openid.claimed_id'] = provider.claimedIdentifier;
      if (provider.localIdentifier) {
        params['openid.identity'] = provider.localIdentifier;
      } else {
        params['openid.identity'] = provider.claimedIdentifier;
      }
    } else if (provider.version.indexOf('2.0') !== -1) {
      params['openid.claimed_id'] = params['openid.identity'] =
        'http://specs.openid.net/auth/2.0/identifier_select';
    } else {
      return reject({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' });
    }

    if (assoc_handle) {
      params['openid.assoc_handle'] = assoc_handle;
    }

    if (returnUrl) {
      // Value should be missing if RP does not want
      // user to be sent back
      params['openid.return_to'] = returnUrl;
    }

    if (realm) {
      if (provider.version.indexOf('2.0') !== -1) {
        params['openid.realm'] = realm;
      } else {
        params['openid.trust_root'] = realm;
      }
    } else if (!returnUrl) {
      return reject({ message: 'No return URL or realm specified' });
    }

    resolve(buildUrl(provider.endpoint, params));
  })
}

/* ==================================================================
 * Extensions
 * ================================================================== 
 */

function _getExtensionAlias(params, ns) {
  for (let k in params)
    if (params[k] == ns)
      return k.replace("openid.ns.", "");
}

/* 
 * Simple Registration Extension
 * http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
 */

let sreg_keys = ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone'];

openid.SimpleRegistration = function SimpleRegistration(options) {
  this.requestParams = { 'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1' };
  if (options.policy_url)
    this.requestParams['openid.sreg.policy_url'] = options.policy_url;
  let required = [];
  let optional = [];
  for (let i = 0; i < sreg_keys.length; i++) {
    let key = sreg_keys[i];
    if (options[key]) {
      if (options[key] == 'required') {
        required.push(key);
      }
      else {
        optional.push(key);
      }
    }
    if (required.length) {
      this.requestParams['openid.sreg.required'] = required.join(',');
    }
    if (optional.length) {
      this.requestParams['openid.sreg.optional'] = optional.join(',');
    }
  }
};

openid.SimpleRegistration.prototype.fillResult = function (params, result) {
  let extension = _getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') || 'sreg';
  for (let i = 0; i < sreg_keys.length; i++) {
    let key = sreg_keys[i];
    if (params['openid.' + extension + '.' + key]) {
      result[key] = params['openid.' + extension + '.' + key];
    }
  }
};

/* 
 * User Interface Extension
 * http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html 
 */
openid.UserInterface = function UserInterface(options) {
  if (typeof (options) != 'object') {
    options = { mode: options || 'popup' };
  }

  this.requestParams = { 'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0' };
  for (let k in options) {
    this.requestParams['openid.ui.' + k] = options[k];
  }
};

openid.UserInterface.prototype.fillResult = function (params, result) {
  // TODO: Fill results
}

/* 
 * Attribute Exchange Extension
 * http://openid.net/specs/openid-attribute-exchange-1_0.html 
 * Also see:
 *  - http://www.axschema.org/types/ 
 *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
 */

let attributeMapping =
{
  'http://axschema.org/contact/country/home': 'country'
  , 'http://axschema.org/contact/email': 'email'
  , 'http://axschema.org/namePerson/first': 'firstname'
  , 'http://axschema.org/pref/language': 'language'
  , 'http://axschema.org/namePerson/last': 'lastname'
  // The following are not in the Google document:
  , 'http://axschema.org/namePerson/friendly': 'nickname'
  , 'http://axschema.org/namePerson': 'fullname'
};

openid.AttributeExchange = function AttributeExchange(options) {
  this.requestParams = {
    'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
    'openid.ax.mode': 'fetch_request'
  };
  let required = [];
  let optional = [];
  for (let ns in options) {
    if (!hasOwnProperty(options, ns)) { continue; }
    if (options[ns] == 'required') {
      required.push(ns);
    }
    else {
      optional.push(ns);
    }
  }
  let self = this;
  required = required.map(function (ns, i) {
    let attr = attributeMapping[ns] || 'req' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  optional = optional.map(function (ns, i) {
    let attr = attributeMapping[ns] || 'opt' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  if (required.length) {
    this.requestParams['openid.ax.required'] = required.join(',');
  }
  if (optional.length) {
    this.requestParams['openid.ax.if_available'] = optional.join(',');
  }
}

openid.AttributeExchange.prototype.fillResult = function (params, result) {
  let extension = _getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') || 'ax';
  let regex = new RegExp('^openid\\.' + extension + '\\.(value|type|count)\\.(\\w+)(\\.(\\d+)){0,1}$');
  let aliases = {};
  let counters = {};
  let values = {};
  for (let k in params) {
    if (!hasOwnProperty(params, k)) { continue; }
    let matches = k.match(regex);
    if (!matches) {
      continue;
    }
    if (matches[1] == 'type') {
      aliases[params[k]] = matches[2];
    }
    else if (matches[1] == 'count') {
      //counter sanitization
      let count = parseInt(params[k], 10);

      // values number limitation (potential attack by overflow ?)
      counters[matches[2]] = (count < AX_MAX_VALUES_COUNT) ? count : AX_MAX_VALUES_COUNT;
    }
    else {
      if (matches[3]) {
        //matches multi-value, aka "count" aliases

        //counter sanitization
        let count = parseInt(matches[4], 10);

        // "in bounds" verification
        if (count > 0 && count <= (counters[matches[2]] || AX_MAX_VALUES_COUNT)) {
          if (!values[matches[2]]) {
            values[matches[2]] = [];
          }
          values[matches[2]][count - 1] = params[k];
        }
      }
      else {
        //matches single-value aliases
        values[matches[2]] = params[k];
      }
    }
  }
  for (let ns in aliases) {
    if (aliases[ns] in values) {
      result[aliases[ns]] = values[aliases[ns]];
      result[ns] = values[aliases[ns]];
    }
  }
}

openid.OAuthHybrid = function (options) {
  this.requestParams = {
    'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
    'openid.oauth.consumer': options['consumerKey'],
    'openid.oauth.scope': options['scope']
  };
}

openid.OAuthHybrid.prototype.fillResult = function (params, result) {
  let extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/oauth/1.0') || 'oauth'
    , token_attr = 'openid.' + extension + '.request_token';


  if (params[token_attr] !== undefined) {
    result['request_token'] = params[token_attr];
  }
};

/* 
 * Provider Authentication Policy Extension (PAPE)
 * http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
 * 
 * Note that this extension does not validate that the provider is obeying the
 * authentication request, it only allows the request to be made.
 *
 * TODO: verify requested 'max_auth_age' against response 'auth_time'
 * TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'
 * TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'
 *
 */

/* Just the keys that aren't open to customisation */
let pape_request_keys = ['max_auth_age', 'preferred_auth_policies', 'preferred_auth_level_types'];
let pape_response_keys = ['auth_policies', 'auth_time']

/* Some short-hand mappings for auth_policies */
let papePolicyNameMap =
{
  'phishing-resistant': 'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant',
  'multi-factor': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
  'multi-factor-physical': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical',
  'none': 'http://schemas.openid.net/pape/policies/2007/06/none'
}

openid.PAPE = function PAPE(options) {
  this.requestParams = { 'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0' };
  for (let k in options) {
    if (k === 'preferred_auth_policies') {
      this.requestParams['openid.pape.' + k] = _getLongPolicyName(options[k]);
    } else {
      this.requestParams['openid.pape.' + k] = options[k];
    }
  }
  let util = require('util');
};

/* you can express multiple pape 'preferred_auth_policies', so replace each
 * with the full policy URI as per papePolicyNameMapping. 
 */
function _getLongPolicyName(policyNames) {
  let policies = policyNames.split(' ');
  for (let i = 0; i < policies.length; i++) {
    if (policies[i] in papePolicyNameMap) {
      policies[i] = papePolicyNameMap[policies[i]];
    }
  }
  return policies.join(' ');
}

function _getShortPolicyName(policyNames) {
  let policies = policyNames.split(' ');
  for (let i = 0; i < policies.length; i++) {
    for (shortName in papePolicyNameMap) {
      if (papePolicyNameMap[shortName] === policies[i]) {
        policies[i] = shortName;
      }
    }
  }
  return policies.join(' ');
}

openid.PAPE.prototype.fillResult = function (params, result) {
  let extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/pape/1.0') || 'pape';
  let paramString = 'openid.' + extension + '.';
  let thisParam;
  for (let p in params) {
    if (hasOwnProperty(params, p)) {
      if (p.substr(0, paramString.length) === paramString) {
        thisParam = p.substr(paramString.length);
        if (thisParam === 'auth_policies') {
          result[thisParam] = _getShortPolicyName(params[p]);
        } else {
          result[thisParam] = params[p];
        }
      }
    }
  }
}
