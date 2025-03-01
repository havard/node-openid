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

const axios = require('axios');
const cookiejar = require('axios-cookiejar-support');
const toughCookie = require('tough-cookie');
const openid = require('../openid');
jest.useFakeTimers();

const relyingParty = new openid.RelyingParty(
  `http://localhost:12345/verify`, // Verification URL (yours)
  null, // Realm (optional, specifies realm for OpenID authentication)
  false, // Use stateless verification
  false, // Strict mode
  []); // List of extensions to enable and include

test('Authenticate with https://www.peercraft.com/', done => {
  const jar = new toughCookie.CookieJar();
  const client = cookiejar.wrapper(axios.create({ jar: jar, withCredentials: true, baseURL: 'https://www.peercraft.com' }));
  relyingParty.authenticate('https://www.peercraft.com/', false,
    (error, url) => {
      expect(error).toBeFalsy();
      client.get(url, { withCredentials: true }).then((res => {
        let loginForm = res.data.indexOf('action="/login/"');
        expect(loginForm).not.toBe(-1);
        client.post('/login/', 'action=password&login=nodeopenidtest@gmail.com&password=' + Buffer.from('VGVoU2VjcmV0IQ==', 'base64').toString('utf-8')).then(res => {
          let subscribeForm = res.data.indexOf('action="/portals/settings');
          if (subscribeForm !== -1) {
            const action = res.data.substring(subscribeForm + 8, res.data.indexOf('"', subscribeForm + 8));
            const hashStart = res.data.indexOf('name="hash" value="');
            expect(hashStart).not.toBe(-1);
            const hash = res.data.substring(hashStart + 19, res.data.indexOf('"', hashStart + 19));
            client.post(action, 'action=update&goto=0&hash=' + hash).then((res) => {
              const linkIndex = res.data.indexOf('seconds, you may <a href="');
              expect(linkIndex).not.toBe(-1);
              const url = res.data.substring(linkIndex + 26, res.data.indexOf('"', linkIndex + 26));
              relyingParty.verifyAssertion(url, (error, result) => {
                expect(error).toBeFalsy();
                expect(result.authenticated).toBeTruthy();
                done();
              });
            });
          }
          else {
            const linkIndex = res.data.indexOf('seconds, you may <a href="');
            expect(linkIndex).not.toBe(-1);
            const url = res.data.substring(linkIndex + 26, res.data.indexOf('"', linkIndex + 26));
            relyingParty.verifyAssertion(url, (error, result) => {
              expect(error).toBeFalsy();
              expect(result.authenticated).toBeTruthy();
              done();
            });
          }
        });
      }));
    });
}, 15000);
