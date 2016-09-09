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

var constants = require('constants');
var https = require('https');
var openid = require('../openid');
var sinon = require('sinon');

// OpenSSL seems to have issues with some servers and causes some of the
// following test cases to fail in Node 0.10.x unless we disable TLS 1.2. See
// https://github.com/joyent/node/issues/5360
https.globalAgent.options.secureOptions = constants.SSL_OP_NO_TLSv1_2;

var clock;

exports.setUp = function(callback)
{
  // By default the openid module save association data to memory and sets up
  // a timer to expire stale entries. This timer prevents the test cases from
  // exiting so we fake the timer implementation during the test run.
  clock = sinon.useFakeTimers('setTimeout');
  callback();
}

exports.tearDown = function(callback)
{
  clock.restore();
  delete clock;
  callback();
}

exports.testResolveFailed = function(test)
{
  openid.authenticate('example.com', 'http://example.com/verify', null, false, false,
    function(error, url)
    {
      test.ok(error);
      test.equal(null, url);
      test.done();
    });
}

exports.testEmptyUrl = function(test)
{
  openid.discover('', 
    true,
    function(error, providers)
    {
      test.ok(error);
      test.equal(null, providers);
      test.done();
    });
}

// 2016-09-09: XRI.net certificate has expired as of 2016-08-15, 
// so disable this test for now.

// exports.testResolveRyanXri = function(test)
// {
//   openid.discover('=ryan',
//     true,
//     function(error, providers)
//     {
//       test.ok(!error);
//       test.equal(2, providers.length);
//       test.done();
//     });
// }

exports.testResolveUbuntu = function(test)
{
  openid.discover('https://login.ubuntu.com',
    true,
    function(error, providers)
    {
      test.ok(!error);
      test.equal(1, providers.length);
      test.done();
    });
}

exports.testResolveLiveJournalUser = function(test)
{
  openid.discover('http://omnifarious.livejournal.com/',
    true,
    function(error, providers)
    {
      test.ok(!error);
      test.equal(1, providers.length);
      test.done();
    });
}

exports.testResolveOpenID11 = function(test)
{
  // FIXME: relying on a third party for back-level protocol support is brittle.
  openid.discover('http://pupeno.com/',
    true,
    function(error, providers)
    {
      test.ok(!error);
      test.notEqual(null, providers);
      test.equal(1, providers.length);
      test.equal(providers[0].version, 'http://openid.net/signon/1.1');
      test.done();
    });
}

function associateTest(url, version, test)
{
  if (arguments.length == 2)
  {
    test = version;
    version = null;
  }

  openid.discover(url,
    true,
    function(error, providers)
    {
      var provider = providers[0];
      openid.associate(provider, function(error, result)
      {
        test.ok(!error);
        if (version)
        {
          test.equal(provider.version, version);
        }
        test.ok(result.expires_in);
        test.done();
      });
    }
  );
}

exports.testAssociateWithUbuntu = function(test)
{
  associateTest('https://login.ubuntu.com', test);
}

exports.testAssociateWithLiveJournal = function(test)
{
  associateTest('http://omnifarious.livejournal.com/', test);
}

exports.testAssociateWithOpenID11 = function(test)
{
  // FIXME: relying on a third party for back-level protocol support is brittle.
  associateTest('https://matt.wordpress.com/', 'http://openid.net/signon/1.1', test);
}

exports.testImmediateAuthenticationWithUbuntu = function(test)
{
  openid.authenticate('https://login.ubuntu.com', 
  'http://example.com/verify', null, true, false, function(error, url)
  {
    test.ok(!error, error);
    test.ok(url.indexOf('checkid_immediate') !== -1);
    test.done();
  });
}

exports.testSetupAuthenticationWithUbuntu = function(test)
{
  openid.authenticate('https://login.ubuntu.com', 
  'http://example.com/verify', null, false, false, function(error, url)
  {
    test.ok(!error);
    test.ok(url.indexOf('checkid_setup') !== -1);
    test.done();
  });
}

exports.testAuthenticationWithUbuntuUsingRelyingPartyObject = function(test)
{
  var rp = new openid.RelyingParty(
      'http://example.com/verify',
      null,
      false,
      false,
      null);
  rp.authenticate('https://login.ubuntu.com', false, function(error, url)
  {
    test.ok(!error);
    test.ok(url.indexOf('checkid_setup') !== -1);
    test.done();
  });
}
