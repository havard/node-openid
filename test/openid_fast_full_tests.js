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

var openid = require('../openid'),
    nock = require('nock');

exports.setUp = function (callback) {
    nock.disableNetConnect();
    nock('https://example.com/')
        .get('/')
        .reply(200, '<?xml version="1.0" encoding="UTF-8"?>' +
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
                    { 'content-type': 'application/xrds+xml' });
    callback();
}

exports.tearDown = function (callback) {
    nock.enableNetConnect();
    callback();
}
exports.testXrdsDiscovery = function (test) {
    openid.discover('https://example.com/', true, function (error, providers) {
        test.ok(!error);
        test.ok(providers.length == 1);
        test.ok(providers[0].version == 'http://specs.openid.net/auth/2.0');
        test.ok(providers[0].endpoint == 'https://www.example.com/endpoint/');
        test.ok(providers[0].localIdentifier == 'https://user.example.com/');
        test.done();
    });
};

//exports.testXrdsDiscovery({ ok: function () { }, done: function () { } });