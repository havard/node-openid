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
 */

const { RelyingParty } = require('../dist/cjs/index.js');
jest.useFakeTimers();

test('Identifier without OpenID providers', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('http://example.com/verify', false).catch((error) => {
    expect(error.message).toBe('No providers found for the given identifier');
  })
});

test('Empty identifier', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('', true).catch((error) => {
    expect(error.message).toBe('Invalid identifier');
  })
});

// 2016-09-09: XRI.net certificate has expired as of 2016-08-15, 
// so disable this test for now.

// test('Resolve =ryan XRI', () => {
//   openid.discover('=ryan',
//     true,
//     (error, providers) => {
//       expect(!error).toBe(true);
//       expect(providers.length).toBe(2);
//     });
// });


test('Resolve login.ubuntu.com', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('https://login.ubuntu.com/', false).then((url) => {
    expect(url).toBeTruthy();
    expect(typeof url).toBe('string');
  }).catch(error => {
    expect(error).toBeFalsy()
  })
});

test('Resolve LiveJournal user', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('http://omnifarious.livejournal.com/', false).then((url) => {
    expect(url).toBeTruthy();
    expect(typeof url).toBe('string');
  }).catch(error => {
    expect(error).toBeFalsy()
  })
});

test('Resolve OpenID 1.1 provider', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  // FIXME: relying on a third party for back-level protocol support is brittle.
  rp.discover('http://pupeno.com/').then((providers) => {
    expect(providers.length).toBe(1);
    expect(providers[0].version).toBe('http://openid.net/signon/1.1');
  }).catch(error => {
      expect(error).toBeFalsy();
    })
});

const performAssociation = (url, version) => {
  return new Promise((resolve, reject) => {
    const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

    rp.discover(url, true).then((providers) => {
      const provider = providers[0];
      rp.associate(provider).then((result) => {
        if (version) {
          expect(provider.version).toBe(version);
        }
        
        expect(result.expires_in).toBeTruthy();

        resolve();
      }).catch((error) => {
        expect(error).toBeFalsy();
        
        reject();
      })
    }).catch((error) => {
      expect(error).toBeFalsy();

      reject();
    })
  })
}

test('Associate with https://login.ubuntu.com', async () => {
  await performAssociation('https://login.ubuntu.com');
});

test('Associate with http://omnifarious.livejournal.com/', async () => {
  await performAssociation('http://omnifarious.livejournal.com/');
});

test('Immediate authentication with https://login.ubuntu.com', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('https://login.ubuntu.com', true).then((url) => {
    expect(url.indexOf('checkid_immediate')).not.toBe(-1);
  }).catch(error => {
    expect(error).toBeFalsy()
  })
});

test('Setup authentication with https://login.ubuntu.com', () => {
  const rp = new RelyingParty('http://example.com/verify', null, false, false, []);

  rp.authenticate('https://login.ubuntu.com', false).then((url) => {
    expect(url.indexOf('checkid_setup')).not.toBe(-1);
  }).catch(error => {
    expect(error).toBeFalsy()
  })
});