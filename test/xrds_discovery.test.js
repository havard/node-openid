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

test('XRDS providers are parsed', () => {
    jest.mock('../dist/cjs/lib/http.js');
    const http = require('../dist/cjs/lib/http.js');
    http.get.mockImplementation((url, params, redirects) => {
        return new Promise((resolve) => {
            resolve({
                data: '<?xml version="1.0" encoding="UTF-8"?>' +
                    '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"' +
                    'xmlns:openid="http://openid.net/xmlns/1.0">' +
                    '<XRD ref="xri://=example">' +
                    '<Query>*example</Query>' +
                    '<Status ceid="off" cid="verified" code="100"/>' +
                    '<Expires>2008-05-05T00:15:00.000Z</Expires>' +
                    '<ProviderID>xri://=</ProviderID>' +
                    '<Service xmlns="xri://$xrd*($v*2.0)">' +
                    '<Type>http://specs.openid.net/auth/2.0/signon</Type>' +
                    '<URI>https://www.example.com/endpoint/</URI>' +
                    '<LocalID>https://user.example.com/</LocalID>' +
                    '</Service>' +
                    '</XRD>' +
                    '</xrds:XRDS>',
                headers: {
                    'content-type': 'application/xrds+xml'
                },
                status: 200
            })
        });
    });

    const rp = new RelyingParty('http://localhost:8888/login/verify', null, false, false, []);

    rp.discover('https://example.com/').then((providers) => {
        expect(providers.length).toBe(1);
        expect(providers[0].version).toBe('http://specs.openid.net/auth/2.0');
        expect(providers[0].endpoint).toBe('https://www.example.com/endpoint/');
        expect(providers[0].localIdentifier).toBe('https://user.example.com/');
    }).catch((error) => {
        console.log(1, error)
        // expect(error).toBeFalsy();
    })
});
