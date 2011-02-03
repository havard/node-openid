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
require.paths.unshift(__dirname + '/../');

var assert = require('assert');
var openid = require('openid');

exports.testResolveFailed = function(test)
{
  openid.authenticate('example.com', 'http://example.com/verify', null, false,
    function(err, data)
    {
      assert.ok(err);
      test.done();
    });
}

exports.testEmptyUrl = function(test)
{
  openid.discover('',
    function(err, data)
    {
      assert.equal(null, data);
      test.done();
    });
}

exports.testResolveRyanXri = function(test)
{
  openid.discover('=ryan',
    function(err, data)
    {
      assert.equal(2, data.length);
      test.done();
    });
}

exports.testResolveRedirect = function(test)
{
  openid.discover('http://www.myopenid.com/xrds?username=swatinem.myopenid.com',
    function(err, data)
    {
      assert.equal(3, data.length);
      test.done();
    });
}

exports.testResolveGoogle = function(test)
{
  openid.discover('http://www.google.com/accounts/o8/id',
    function(err, data)
    {
      assert.equal(1, data.length);
      test.done();
    });
}

exports.testResolveLiveJournalUser = function(test)
{
  openid.discover('http://omnifarious.livejournal.com/',
    function(err, data)
    {
      assert.equal(1, data.length);
      test.done();
    });
}

exports.testResolveOpenID11 = function(test)
{
  openid.discover('http://www.michaelwales.com/',
    function(err, data)
    {
      assert.equal(1, data.length);
      test.done();
    });
}

function associateTest(url, test)
{
  openid.discover(url,
    function(err, providers)
    {
      var provider = providers[0];
      openid.associate(provider, function(err, data)
      {
        assert.ok(data.expires_in);
        test.done();
      });
    }
  );
}

exports.testAssociateWithGoogle = function(test)
{
  associateTest('http://www.google.com/accounts/o8/id', test);
}

exports.testAssociateWithLiveJournal = function(test)
{
  associateTest('http://omnifarious.livejournal.com/', test);
}

exports.testAssociateWithOpenID11 = function(test)
{
  associateTest('http://www.michaelwales.com/', test);
}

exports.testImmediateAuthenticationWithGoogle = function(test)
{
  openid.authenticate('http://www.google.com/accounts/o8/id', 
  'http://licensing.ox.no:8080/verify', null, true, function(err, url)
  {
    assert.ok(url.indexOf('checkid_immediate') !== -1);
    test.done();
  });
}

exports.testSetupAuthenticationWithGoogle = function(test)
{
  openid.authenticate('http://www.google.com/accounts/o8/id', 
  'http://licensing.ox.no:8080/verify', null, false, function(err, url)
  {
    assert.ok(url.indexOf('checkid_setup') !== -1);
    test.done();
  });
}

exports.testVerificationUrl = function(test)
{
  var result = openid.verifyAssertion('http://fu');
  assert.ok(!result.authenticated);
  test.done();
}
