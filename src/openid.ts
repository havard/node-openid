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
import { Accept, get, post, undefinedAxiosResponse } from './lib/http';
import { parse as xrdsParse } from './lib/xrds';
import Extension from './extension';
import { hasOwnProperty, isValidDate } from './lib/util';
import { Realm, Association, Provider, RequestOrUrl, ErrorMessage, AssertionResponse, /*isRequest,*/ ValidityChecks } from './types';

export class RelyingParty {
  readonly returnUrl: string;
  readonly realm: Realm;
  readonly stateless: boolean;
  readonly strict: boolean;
  readonly extensions: Extension[];
  readonly validityChecks?: ValidityChecks;

  #associations: Record<string, Association> = {};
  #discoveries: Record<string, Provider> = {};
  #nonces: Record<string, Date> = {};

  /**
   * 
   * @param returnUrl Verification URL
   * @param realm Realm (optional, specifies realm for OpenID authentication)
   * @param stateless Use stateless verification
   * @param strict Strict mode
   * @param extensions List of Extension(s) to enable and include
   * @param validityChecks Optional safety checks, recommended to turn on.
   */
  constructor(returnUrl: string, realm: Realm, stateless: boolean, strict: boolean, extensions: Extension[], validityChecks?: ValidityChecks) {
    this.returnUrl = returnUrl;
    this.realm = realm || null;
    this.stateless = stateless;
    this.strict = strict;
    this.extensions = extensions;
    this.validityChecks = validityChecks;
  }

  async authenticate(identifier: string, immediate: boolean) {
    return new Promise<string>(async (resolve, reject) => {
      const providers = await this.#discover(identifier).catch((e) => {
        reject(e);
      });

      if (providers === undefined || providers.length === 0) {
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
        if (rp.stateless) {
          const url = await rp.#requestAuthentication(currentProvider, null, immediate).catch(chooseProvider);

          if (!url) {
            return;
          }

          return chooseProvider(undefined, url);
        }

        const answer = await rp.#associate(currentProvider).catch(chooseProvider);

        if (!answer) {
          return;
        }

        if (answer.error) {
          return chooseProvider(error || {
            message: answer.error
          });
        }

        const url = await rp.#requestAuthentication(currentProvider, answer.assoc_handle, immediate).catch(chooseProvider);

        if (url) {
          chooseProvider(undefined, url);
        }
      })();
    })
  }

  /**
   * 
   * @param requestOrUrl node:http.ClientRequest or URL object or URL string.
   * @returns 
   */
  async verifyAssertion(requestOrUrl: RequestOrUrl): Promise<AssertionResponse> {
    return new Promise(async (resolve, reject) => {
      /*if (isRequest(requestOrUrl)) {
        if (requestOrUrl.method.toUpperCase() == 'POST') {
          if ((requestOrUrl.getHeader('content-type')?.toString() || '').toLowerCase().indexOf('application/x-www-form-urlencoded') === 0) {
            // POST response received
            let data = '';

            requestOrUrl.on('data', (chunk) => {
              data += chunk;
            });

            requestOrUrl.on('end', async () => {
              let params = (new URLSearchParams(data));

              let assertResponse = await this.#verifyAssertionData(params).catch((e) => {
                return reject(e);
              });

              if (!assertResponse) {
                return;
              }

              return resolve(assertResponse);
            });
          } else {
            return reject({ message: 'Invalid POST response from OpenID provider' });
          }

          return;
        } else if (requestOrUrl.method.toUpperCase() !== 'GET') {
          return reject({ message: 'Invalid request method from OpenID provider' });
        }
      }*/

      let assertionUrl: URL;
      try {
        /*if (isRequest(requestOrUrl)) {
          assertionUrl = new URL(requestOrUrl.url);
        } else*/ if (requestOrUrl instanceof URL) {
          assertionUrl = requestOrUrl;
        } else {
          assertionUrl = new URL(requestOrUrl);
        }

        if (!verifyReturnUrl(assertionUrl, new URL(this.returnUrl))) {
          return reject({ message: 'Invalid return URL' });
        }
      } catch (_) {
        return reject({ message: 'Invalid return URL' });
      }

      let assertResponse = await this.#verifyAssertionData(assertionUrl.searchParams).catch((e) => {
        reject(e);
      });

      if (!assertResponse) {
        return;
      }

      return resolve(assertResponse);
    })
  }

  /**
   * This function is only available to be used by tests, as it can be accessed from outside but should not be visible.
   * @param abnormalIdentifier 
   * @returns 
   */
  private discover(abnormalIdentifier: string): Promise<Provider[]> {
    return this.#discover(abnormalIdentifier);
  }

  #discover(abnormalIdentifier: string) {
    return new Promise<Provider[]>(async (resolve, reject) => {
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
          const providers = await this.#resolveHostMeta(identifier).catch(_ => {
            return [] as Provider[];
          })

          return resolve(providers);
        }

        return resolve(providers);
      }

      // Add claimed identifier to providers with local identifiers
      // and OpenID 1.0/1.1 providers to ensure correct resolution 
      // of identities and services
      for (let provider of providers) {
        if (!provider.claimedIdentifier &&
          (provider.localIdentifier || provider.version.indexOf('2.0') === -1)) {
          provider.claimedIdentifier = identifier;
        }
      }

      return resolve(providers);
    })
  }

  /**
   * This function alias is only available to be used by tests, as it can be accessed from outside but should not be visible.
   * @returns 
   */
  private associate(provider: Provider, algorithm = 'DH-SHA256'): Promise<Record<string, string>> {
    return this.#associate(provider, algorithm);
  }

  async #associate(provider: Provider, algorithm = 'DH-SHA256'): Promise<Record<string, string>> {
    return new Promise(async (resolve, reject) => {
      let params = generateAssociationRequestParameters(provider.version, algorithm);
      if (!algorithm) {
        algorithm = 'DH-SHA256';
      }

      let dh: crypto.DiffieHellman | undefined = undefined;
      if (!algorithm.includes('no-encryption')) {
        dh = createDiffieHellmanKeyExchange(algorithm);
        params.set('openid.dh_modulus', bigIntToBase64(dh.getPrime('binary')));
        params.set('openid.dh_gen', bigIntToBase64(dh.getGenerator('binary')));
        params.set('openid.dh_consumer_public', bigIntToBase64(dh.getPublicKey('binary')));
      }

      const { data: responseData, status } = await post(provider.endpoint, params).catch(_ => {
        reject({ message: 'HTTP request failed' });

        return undefinedAxiosResponse;
      })

      if (status !== 200 && status !== 400) {
        return reject({ message: 'HTTP request failed' });
      }

      let data = decodePostData(responseData);

      if (data.error_code === 'unsupported-type' || !data.ns) {
        if (algorithm === 'DH-SHA1') {
          if (this.strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
            return reject({ message: 'Channel is insecure and no encryption method is supported by provider' });
          } else {
            return resolve(this.#associate(provider, 'no-encryption-256'));
          }
        } else if (algorithm === 'no-encryption-256') {
          if (this.strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
            return reject({ message: 'Channel is insecure and no encryption method is supported by provider' });
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
            return resolve(this.#associate(provider, 'no-encryption'));
          }
        } else if (algorithm === 'DH-SHA256') {
          return resolve(this.#associate(provider, 'DH-SHA1'));
        }
      }

      if (data.error) {
        return reject({ message: data.error })
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

        try {
          secret = base64encode(xor(encMacKey, sharedSecret));
        } catch (error) {
          return reject(error as ErrorMessage);
        }
      }

      if (!data.assoc_handle) {
        return reject({ message: 'OpenID provider does not seem to support association; you need to use stateless mode' })
      }

      this.#saveAssociation(provider, hashAlgorithm,
        data.assoc_handle, secret, parseInt(data.expires_in));

      return resolve(data);
    })
  }

  async #requestAuthentication(provider: Provider, assoc_handle: string | null, immediate: Boolean): Promise<string> {
    return new Promise((resolve, reject) => {
      let params: Record<string, string> = {
        'openid.mode': immediate ? 'checkid_immediate' : 'checkid_setup'
      };

      if (provider.version.indexOf('2.0') !== -1) {
        params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
      }

      for (let extension of this.extensions) {
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
        return reject({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' })
      }

      if (assoc_handle) {
        params['openid.assoc_handle'] = assoc_handle;
      }

      if (this.returnUrl) {
        // Value should be missing if RP does not want
        // user to be sent back
        params['openid.return_to'] = this.returnUrl;
      }

      if (this.realm) {
        if (provider.version.indexOf('2.0') !== -1) {
          params['openid.realm'] = this.realm;
        } else {
          params['openid.trust_root'] = this.realm;
        }
      } else if (!this.returnUrl) {
        return reject({ message: 'No return URL or realm specified' });
      }

      return resolve(buildUrl(provider.endpoint, params));
    })
  }

  #verifyAssertionData(params: URLSearchParams): Promise<AssertionResponse> {
    return new Promise(async (resolve, reject) => {
      let assertionError = this.#getAssertionError(params);
      if (assertionError) {
        return reject({ message: assertionError });
      }

      if (!this.#invalidateAssociationHandleIfRequested(params)) {
        return reject({ message: 'Unable to invalidate association handle' });
      }

      if (!this.#checkNonce(params)) {
        return reject({ message: 'Invalid or replayed nonce' });
      }

      let response = await this.#verifyDiscoveredInformation(params).catch((error: ErrorMessage) => {
        reject(error);
      });

      if (response !== undefined) {
        resolve(response);
      }
    })
  };

  #verifyDiscoveredInformation(params: URLSearchParams) {
    return new Promise<AssertionResponse>(async (resolve, reject) => {
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
          return resolve({ authenticated: false });
        }
      }

      if (useLocalIdentifierAsKey) {
        claimedIdentifier = params.get('openid.identity');

        // If validityChecks are enabled, check that the identity is valid
        if (this.validityChecks && claimedIdentifier !== null) {
          let invalidCount = 0;

          for (let identity of this.validityChecks.identity) {
            if (!claimedIdentifier.startsWith(identity)) {
              invalidCount++
            }
          }

          if (this.validityChecks.identity.length === invalidCount) {
            return reject({ message: 'Identifier failed to pass validity checks' });
          }
        }
      } else {
        // If validityChecks are enabled, check that the claimed_id is valid
        if (this.validityChecks && claimedIdentifier !== null) {
          let invalidCount = 0;

          for (let identity of this.validityChecks.claimed_id) {
            if (!claimedIdentifier.startsWith(identity)) {
              invalidCount++
            }
          }

          if (this.validityChecks.claimed_id.length === invalidCount) {
            return reject({ message: 'Claimed identifier failed to pass validity checks' });
          }
        }
      }

      if (!claimedIdentifier) {
        return reject({ message: 'No claimed identifier found.' });
      }

      // Check that ns and op_endpoint passed validity checks if enabled
      if (this.validityChecks) {
        const ns = params.get('openid.ns');

        if (ns !== null && !this.validityChecks.ns.includes(ns)) {
          return reject({ message: 'NS failed to pass validity checks' });
        }

        const op_endpoint = params.get('openid.op_endpoint');

        if (op_endpoint !== null && !this.validityChecks.op_endpoint.includes(op_endpoint)) {
          return reject({ message: ' failed to pass validity checks' });
        }
      }

      claimedIdentifier = this.#getCanonicalClaimedIdentifier(claimedIdentifier);

      const provider = this.#loadDiscoveredInformation(claimedIdentifier);

      if (provider) {
        return resolve(this.#verifyAssertionAgainstProviders([provider], params));
      } else if (useLocalIdentifierAsKey) {
        return reject({ message: 'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.' });
      }

      const providers = await this.#discover(claimedIdentifier).catch((error: ErrorMessage) => {
        reject(error);
      })

      if (providers === undefined) {
        return;
      }

      if (!providers.length) {
        return reject({ message: 'No OpenID provider was discovered for the asserted claimed identifier' });
      }

      return resolve(await this.#verifyAssertionAgainstProviders(providers, params));
    });
  }

  #verifyAssertionAgainstProviders(providers: Provider[], params: URLSearchParams) {
    return new Promise<AssertionResponse>(async (resolve, reject) => {
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
              return reject({ message: 'Provider has claimedIdentifier but url lacks openid.claimed_id' });
            }

            let claimedIdentifier = this.#getCanonicalClaimedIdentifier(p_claimed_id);
            if (provider.claimedIdentifier != claimedIdentifier) {
              return reject({ message: 'Claimed identifier in assertion response does not match discovered claimed identifier' });
            }
          }
        }

        if (!!provider.localIdentifier && provider.localIdentifier != params.get('openid.identity')) {
          return reject({ message: 'Identity in assertion response does not match discovered local identifier' });
        }

        let result = await this.#checkSignature(params, provider).catch((error: ErrorMessage) => {
          reject(error)
        });

        if (!result) {
          return;
        }

        if (this.extensions && result.authenticated) {
          for (let extension of this.extensions) {
            extension.fillResult(params, result);
          }
        }

        return resolve(result);
      }

      return reject({ message: 'No valid providers were discovered for the asserted claimed identifier' });
    });
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
    const invalidate_handle = params.get('openid.invalidate_handle');

    if (params.get('is_valid') === 'true' && invalidate_handle !== null) {
      if (!this.#removeAssociation(invalidate_handle)) {
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

  #checkSignature(params: URLSearchParams, provider: Provider) {
    return new Promise<AssertionResponse>(async (resolve, reject) => {
      if (!params.get('openid.signed') || !params.get('openid.sig')) {
        return reject({ message: 'No signature in response' });
      }

      let assertionResponse: void | AssertionResponse = undefined;

      if (this.stateless) {
        assertionResponse = await this.#checkSignatureUsingProvider(params, provider).catch((error: ErrorMessage) => {
          reject(error);
        });
      } else {
        // Using try catch only due to not having a promise, otherwise avoid
        try {
          assertionResponse = this.#checkSignatureUsingAssociation(params);
        } catch (error: unknown) {
          reject(error as ErrorMessage);
        }
      }

      if (assertionResponse) {
        return resolve(assertionResponse);
      }
    });
  }

  // Again, only use throw in non-promise functions
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
    return new Promise<AssertionResponse>(async (resolve, reject) => {
      let requestParams: URLSearchParams = new URLSearchParams();

      requestParams.set('openid.mode', 'check_authentication');

      params.forEach((value, key) => {
        if (key === 'openid.mode') {
          return;
        }

        requestParams.set(key, value);
      })

      const { data: responseData, status } = await post(params.get('openid.ns') ? (params.get('openid.op_endpoint') || provider.endpoint) : provider.endpoint, requestParams)
        .catch((error: ErrorMessage) => {
          reject(error);

          return undefinedAxiosResponse;
        })

      if (status !== 200 || responseData == null) {
        return reject({ message: 'Invalid assertion response from provider' });
      } else {
        let data = decodePostData(responseData);

        if (data['is_valid'] == 'true') {
          return resolve({
            authenticated: true,
            claimedIdentifier: provider.version.indexOf('2.0') !== -1 ? params.get('openid.claimed_id') : params.get('openid.identity')
          });
        } else {
          return reject({ message: 'Invalid signature' });
        }
      }
    });
  }

  #resolveHostMeta(identifier: string, fallBackToProxy = false): Promise<Provider[]> {
    return new Promise<Provider[]>(async (resolve, reject) => {
      let host = new URL(identifier);
      let hostMetaUrl: string;
      if (fallBackToProxy && !this.strict) {
        hostMetaUrl = 'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host;
      } else {
        hostMetaUrl = host.protocol + '//' + host.host + '/.well-known/host-meta';
      }

      if (!hostMetaUrl) {
        return reject({ message: 'Invalid host meta identifier' });
      } else {
        const { data, status } = await get(hostMetaUrl, [Accept.ANY]).catch(error => {
          reject({ message: 'Failed to get hostMetaUrl' });

          return undefinedAxiosResponse;
        });

        if (status != 200) {
          if (!fallBackToProxy && !this.strict) {
            const providers = await this.#resolveHostMeta(identifier, true).catch((error: ErrorMessage) => {
              reject(error);
            });

            if (providers === undefined) {
              return;
            }

            return resolve(providers);
          }

          return reject({ message: 'resolveHostMeta recieved status code other than 200' });
        } else {
          // Attempt to parse the data but if this fails it may be because
          // the response to hostMetaUrl was some other http/html resource.
          // Therefore fallback to the proxy if no providers are found.
          const providers = await parseHostMeta(data).catch((error: ErrorMessage) => {
            reject(error);
          });

          if (providers === undefined) {
            return;
          }

          if (providers.length == 0 && !fallBackToProxy && !this.strict) {
            const providers = await this.#resolveHostMeta(identifier, true).catch((error: ErrorMessage) => {
              reject(error);
            })

            if (providers !== undefined) {
              return resolve(providers);
            }
          } else {
            return resolve(providers);
          }
        }
      }
    })
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
    if (this.#associations[handle]) {
      delete this.#associations[handle];

      return true;
    }

    return false;
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
    const search = '?' + (new URLSearchParams(params)).toString();

    return new URL(search, url).toString();
  }

  return url;
}

function verifyReturnUrl(assertionUrl: URL, originalReturnUrl: URL) {
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

function decodePostData(data: string) {
  let lines = data.split('\n');
  let result: Record<string, string> = {};
  for (let line of lines) {
    if (line.length > 0 && line[line.length - 1] == '\r') {
      line = line.substring(0, line.length - 1);
    }

    if (!line.includes(':')) {
      continue;
    }

    let [key, value] = line.split(/:(.*)/);

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

function parseXrds(xrdsUrl: string, xrdsData: string) {
  let services = xrdsParse(xrdsData);
  if (services == null) {
    throw { message: 'No services found in xrds data' };
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

function parseHtml(htmlUrl: string, html: string, hops: number): Promise<Provider[]> {
  return new Promise<Provider[]>(async (resolve, reject) => {
    let metaUrl = matchMetaTag(html);
    if (metaUrl !== null) {
      const providers = await resolveXri(metaUrl, hops + 1).catch((error: ErrorMessage) => {
        reject(error);
      });

      if (providers === undefined) {
        return;
      }

      return resolve(providers);
    }

    let provider = matchLinkTag(html, 'openid2.provider');
    if (provider == null) {
      provider = matchLinkTag(html, 'openid.server');
      if (provider == null) {
        return reject({ message: 'No provider found in parseHtml' });
      }

      let localId = matchLinkTag(html, 'openid.delegate');
      return resolve([{
        version: 'http://openid.net/signon/1.1',
        endpoint: provider,
        claimedIdentifier: htmlUrl,
        localIdentifier: localId
      }])
    }

    let localId = matchLinkTag(html, 'openid2.local_id');
    return resolve([{
      version: 'http://specs.openid.net/auth/2.0/signon',
      endpoint: provider,
      claimedIdentifier: htmlUrl,
      localIdentifier: localId
    }]);
  });
}

function parseHostMeta(hostMeta: string) {
  return new Promise<Provider[]>(async (resolve, reject) => {
    let match = /^Link: <([^\n\r]+?)>;/.exec(hostMeta);
    if (match != null && match.length > 0) {
      const xriUrl = match[1];
      const providers = await resolveXri(xriUrl).catch((error: ErrorMessage) => {
        reject(error);
      });

      if (providers !== undefined) {
        return resolve(providers);
      }
    } else {
      return reject({ message: 'Invalid hostMeta' });
    }
  });
}

async function resolveXri(xriUrl: string, hops = 1) {
  return new Promise<Provider[]>(async (resolve, reject) => {
    if (hops >= 5) {
      return reject({ message: 'Too many hops specified in resolveXri' });
    }

    const { data, headers, status } = await get(xriUrl, [Accept.XRDS, Accept.XML]).catch(_ => {
      reject({ message: 'Failed to get xriUrl' });

      return undefinedAxiosResponse;
    });

    if (status !== 200) {
      return reject({ message: 'resolveXri got status code other than 200' });
    }

    // Endpoint has XRDS (text/xml isn't standard, but some providers use it)
    if (headers['content-type']?.includes('application/xrds+xml') || headers['content-type']?.includes('text/xml')) {
      try {
        const providers = parseXrds(xriUrl, data)

        return resolve(providers);
      } catch (error) {
        return reject(error as ErrorMessage);
      }
    // Endpoint has HTML
    } else if (headers['content-type']?.includes('text/html')) {
      const providers = await resolveHtml(xriUrl, hops + 1, data).catch((error: ErrorMessage) => {
        reject(error);
      })

      if (providers !== undefined) {
        return resolve(providers);
      }
    // Endpoint redirects to other location for XRDS data
    } else if (headers['x-xrds-location']) {
      let xrdsLocation = headers['x-xrds-location'] ?? headers['X-XRDS-Location'];

      const { data, status } = await get(xrdsLocation, [Accept.XRDS]).catch(_ => {
        reject({ message: 'Failed to get xrds from header x-xrds-location' })

        return undefinedAxiosResponse;
      });

      if (status !== 200) {
        return reject({ message: 'xrdsLocation got status code other than 200' });
      }

      try {
        const providers = parseXrds(xrdsLocation, data);

        return resolve(providers);
      } catch (error) {
        return reject(error as ErrorMessage);
      }
    } else {
      return reject({ message: 'Invalid content-type provided by provider xri' })
    }
  })
}

function resolveHtml(identifier: string, hops = 1, data?: any) {
  return new Promise<Provider[]>(async (resolve, reject) => {
    if (hops >= 5) {
      return reject({ message: 'resolveHtml recieved too many hops' });
    }

    if (data == null) {
      const { data, status } = await get(identifier, [Accept.HTML]).catch(_ => {
        reject({ message: 'resolveHtml failed to get identifier' });

        return undefinedAxiosResponse;
      })

      if (status != 200 || data == null) {
        return reject({ message: 'resolveHtml failed to get data' });
      }

      const providers = await parseHtml(identifier, data, hops + 1).catch((error: ErrorMessage) => {
        reject(error);
      })

      if (providers === undefined) {
        return;
      }

      return resolve(providers);
    }

    const providers = await parseHtml(identifier, data, hops).catch((error: ErrorMessage) => {
      reject(error);
    })

    if (providers !== undefined) {
      return resolve(providers);
    }
  })
}

function createDiffieHellmanKeyExchange(algorithm?: string) {
  let defaultPrime = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr';

  let dh = crypto.createDiffieHellman(defaultPrime, 'base64');

  dh.generateKeys();

  return dh;
}

function generateAssociationRequestParameters(version: string, algorithm: string) {
  let params: URLSearchParams = new URLSearchParams({
    'openid.mode': 'associate',
  });

  if (version.indexOf('2.0') !== -1) {
    params.set('openid.ns', 'http://specs.openid.net/auth/2.0');
  }

  if (algorithm === 'DH-SHA1') {
    params.set('openid.assoc_type', 'HMAC-SHA1');
    params.set('openid.session_type', 'DH-SHA1');
  } else if (algorithm === 'no-encryption-256') {
    if (version.indexOf('2.0') === -1) {
      params.set('openid.session_type', ''); // OpenID 1.0/1.1 requires blank
      params.set('openid.assoc_type', 'HMAC-SHA1');
    } else {
      params.set('openid.session_type', 'no-encryption');
      params.set('openid.assoc_type', 'HMAC-SHA256');
    }
  } else if (algorithm == 'no-encryption') {
    if (version.indexOf('2.0') !== -1) {
      params.set('openid.session_type', 'no-encryption');
    }

    params.set('openid.assoc_type', 'HMAC-SHA1');
  } else {
    params.set('openid.assoc_type', 'HMAC-SHA256');
    params.set('openid.session_type', 'DH-SHA256');
  }

  return params;
}