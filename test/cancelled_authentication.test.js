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

const openid = require('../openid');

test('Cancelled verification does not authenticate', () => {
    openid.verifyAssertion(
        'http://host/?openid.mode=cancel' +
        '&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0',
        'http://example.com/verify',
        (error, result) => {
            expect(error).toBeTruthy();
            expect(result).toBeFalsy();
        });
});
