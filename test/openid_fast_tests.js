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
var openid = require('../openid');

exports.testVerificationUrl = function(test)
{
  var times = 0;
  openid.verifyAssertion('http://fu', function(error, result)
  {
    test.ok(!times++);
    test.ok(!result || !result.authenticated);
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
    test.ok(!times++);
    test.ok(!result || !result.authenticated);
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
    test.ok(!result || !result.authenticated);
    test.done();
  });
}

exports.testAttributeExchangeRequest = function(test)
{
  var ax = new openid.AttributeExchange(),
      expectedParams = {
        'openid.ns.ax' : 'http://openid.net/srv/ax/1.0',
        'openid.ax.mode' : 'fetch_request'
      }
  
  test.deepEqual(ax.requestParams, expectedParams);
  test.done();
}

var _aliasMap = function(request)
{
  var map = {},
      regex = /^openid\.ax\.type\.(\w+)$/;
  
  for(var key in request)
  {
    var matches = key.match(regex);
    if (matches)
    {
      map[request[key]] = matches[1];
    }
  }
  
  return map;
}

var _checkAxAttributes = function (options, request, test)
{
  var optional = 0,
      required = 0;
  
  test.equal(request.namespace, 'http://openid.net/srv/ax/1.0', 'unexpected namespace');
  test.equal(request.mode, 'fetch_request', 'unexpected mode');
  test.equal(Object.keys(request.aliases).length, Object.keys(options).length, 'incorrect number of aliases');
  for(var attr in options)
  {
    var alias = request.aliases[attr],
        list;
    
    if (options[attr] === 'required')
    {
      list = request.required;
      required++;
    }
    else
    {
      list = request.optional;
      optional++;
    }
    
    test.ok(alias, attr + ' has no alias');
    test.ok(list.indexOf(alias) !== -1, 'alias ' + alias + ' not in expected list');
  }
  test.equal(request.required.length, required, 'invalid number of required attributes');
  test.equal(request.optional.length, optional, 'invalid number of optional attributes');
}

var _parseRequest = function(ax)
{
  var parsedRequest = {
        aliases : _aliasMap(ax.requestParams),
        mode : ax.requestParams['openid.ax.mode'],
        namespace : ax.requestParams['openid.ns.ax'],
        required : [],
        optional : []
      };
  
  if (ax.requestParams['openid.ax.required'])
  {
    parsedRequest.required = ax.requestParams['openid.ax.required'].split(',');
  }
  if (ax.requestParams['openid.ax.if_available'])
  {
    parsedRequest.optional = ax.requestParams['openid.ax.if_available'].split(',');
  }
  
  return parsedRequest;
}

exports.testAttributeExchangeOptions = function(test)
{
  var options = {
        'http://axschema.org/contact/email' : 'required',
        'http://axschema.org/namePerson/friendly' : 'optional',
        'http://example.com/schema/fullname' : 'required',
        'http://example.com/schema/gender' : 'optional'
      },
      request = _parseRequest(new openid.AttributeExchange(options));
  
  test.equal(request.aliases['http://axschema.org/contact/email'], 'email');
  test.equal(request.aliases['http://axschema.org/namePerson/friendly'], 'nickname');
  
  _checkAxAttributes(options, request, test);
  test.done();
}

exports.testAttributeExchangeCustomMapping = function(test)
{
  var mappings = {
      'http://axschema.org/namePerson/friendly' : 'friendly',
      'http://example.com/schema/fullname' : 'fullname'
    },
    options = {
      'http://axschema.org/namePerson/friendly' : 'required',
      'http://example.com/schema/fullname' : 'required'
    },
    request = _parseRequest(new openid.AttributeExchange(options, mappings));
  
  for(var ns in mappings)
  {
    test.equal(request.aliases[ns], mappings[ns], 'unexpected alias');
  }
  
  _checkAxAttributes(options, request, test);
  test.done();
}

exports.testAttributeExchangeResponse = function(test)
{
  var ax = new openid.AttributeExchange(),
      results = {},
      exampleParams = {
        'openid.ax.type.email' :  'http://axschema.org/contact/email',
        'openid.ax.value.email' : 'fred.example@gmail.com',
        'openid.ax.type.language' : 'http://axschema.org/pref/language',
        'openid.ax.value.language' : 'english',
        'openid.ax.type.custom' : 'http://example.com/schema/custom',
        'openid.ax.value.custom' : 'custom attribute'
      }
  ax.fillResult(exampleParams, results);
  
  test.notEqual(results['email'], undefined);
  test.notEqual(results['language'], undefined);
  test.notEqual(results['custom'], undefined);
  
  test.equal('fred.example@gmail.com', results['email']);
  test.equal('english', results['language']);
  test.equal('custom attribute', results['custom']);
  
  test.done();
}

exports.testPape = function(test)
{
  var exampleParams = {
        "openid.pape.auth_time" : new Date().toISOString(),
        "openid.pape.auth_policies" : 'http://schemas.openid.net/pape/policies/2007/06/multi-factor http://schemas.openid.net/pape/policies/2007/06/phishing-resistant'
      };
  var pape = new openid.PAPE(),
      results = {};
  
  pape.fillResult(exampleParams, results);
  test.notEqual(results['auth_time'], undefined);
  test.notEqual(results['auth_policies'], undefined);
  test.equal(results['auth_policies'], "multi-factor phishing-resistant"); 
  test.done();
}

