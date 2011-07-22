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
var assert = require('assert');
var openid = require('../openid');

exports.testVerificationUrl = function(test)
{
  var times = 0;
  openid.verifyAssertion('http://fu', function(error, result)
  {
    assert.ok(!times++);
    assert.ok(!result || !result.authenticated);
    test.done();
  });
}

exports.testVerificationCancel = function(test)
{
  var times = 0;
  openid.verifyAssertion(
      'http://host/?openid.mode=cancel' +
      '&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0',
      function(error, result)
  {
    assert.ok(!times++);
    assert.ok(!result || !result.authenticated);
    test.done();
  });
}

exports.testVerificationUrlUsingRelyingParty = function(test)
{
  var rp = new openid.RelyingParty(
      'http://example.com/verify',
      null,
      false,
      false,
      null);

  rp.verifyAssertion('http://fu', function(error, result)
  {
    assert.ok(!result || !result.authenticated);
    test.done();
  });
}


exports.testAttributeExchange = function(test)
{
  var ax = new openid.AttributeExchange(),
      results = {},
      exampleParams = {
        'openid.ax.type.email' :  'http://axschema.org/contact/email',
        'openid.ax.value.email' : 'fred.example@gmail.com',
        'openid.ax.type.language' : 'http://axschema.org/pref/language',
        'openid.ax.value.language' : 'english'
      }
  ax.fillResult(exampleParams, results);
  
  assert.notEqual(results['email'], undefined);
  assert.notEqual(results['language'], undefined);
  
  assert.equal('fred.example@gmail.com', results['email']);
  assert.equal('english', results['language']);
  
  test.done();
}
