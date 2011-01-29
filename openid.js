/* -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et tw=80 : */
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

require.paths.unshift(__dirname + '/lib');
require.paths.unshift(__dirname);

var bigint = require('bigint'),
    convert = require('convert'),
    crypto = require('crypto'),
    http = require('http'),
    https = require('https'),
    querystring = require('querystring'),
    url = require('url'),
    xrds = require('xrds');

var _associations = {};

var openid = exports;

function _isDef(e)
{
  var undefined;
  return e !== undefined;
}

function _toBase64(bigint)
{
  return convert.base64.encode(convert.btwoc(convert.chars_from_hex(bigint.toString(16))));
}

function _base64ToPlain(str)
{
  return convert.unbtwoc(convert.base64.decode(str));
}

function _fromBase64(str)
{
  return new bigint.BigInteger(convert.hex_from_chars(convert.unbtwoc(convert.base64.decode(str))), 16);
}

function _xor(a, b)
{
  if(a.length != b.length)
  {
    throw new Error('Length must match for xor');
  }

  var r = '';
  for(var i = 0; i < a.length; ++i)
  {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
  }

  return r;
}

openid.saveAssociation = function(type, handle, secret, expiry_time)
{
  setTimeout(function() {
    openid.removeAssociation(handle);
  }, expiry_time);
  _associations[handle] = {type : type, secret: secret};
}

openid.loadAssociation = function(handle)
{
  if(_isDef(_associations[handle]))
  {
    return _associations[handle];
  }

  return null;
}

openid.removeAssociation = function(handle)
{
  delete _associations[handle];
  return true;
}

function _buildUrl(theUrl, params)
{
  theUrl = url.parse(theUrl);
  if(params)
  {
    if(!theUrl.query)
    {
      theUrl.query = params;
    }
    else
    {
      theUrl.query = querystring.parse(theUrl.query);
      for(var key in params)
      {
        if(params.hasOwnProperty(key))
        {
          theUrl.query[key] = params[key];
        }
      }
    }
  }

  return url.format(theUrl);
}

function _get(getUrl, params, callback, redirects)
{
  redirects = redirects || 5;
  getUrl = url.parse(_buildUrl(getUrl, params));

  var path = getUrl.pathname || '/';
  if(getUrl.query)
  {
    path += '?' + getUrl.query;
  }
  var options = {
    host: getUrl.hostname,
    port: _isDef(getUrl.port) ? getUrl.port :
      (getUrl.protocol == 'https:' ? 443 : 80),
    path: path
  };
  (getUrl.protocol == 'https:' ? https : http).get(options, function(res)
  {
    var data = '';
    res.on('data', function(chunk)
    {
      data += chunk;
    });

    res.on('end', function()
    {
      if(res.headers.location && --redirects)
      {
        _get(res.headers.location, params, callback, redirects);
      }
      else
      {
        callback(data, res.headers, res.statusCode);
      }
    });
  }).on("error", function () {
    callback();
  });
}

function _post(getUrl, data, callback, redirects)
{
  redirects = redirects || 5;
  getUrl = url.parse(getUrl);

  var path = getUrl.pathname || '/';
  if(getUrl.query)
  {
    path += '?' + getUrl.query;
  }

  var encodedData = _encodePostData(data);
  var options = {
    host: getUrl.hostname,
    port: _isDef(getUrl.port) ? getUrl.port :
      (getUrl.protocol == 'https:' ? 443 : 80),
    path: path,
    headers: {'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': encodedData.length},
    method: 'POST'
  };
  (getUrl.protocol == 'https:' ? https : http).request(options, function(res)
  {
    var data = '';
    res.on('data', function(chunk)
    {
      data += chunk;
    });

    res.on('end', function()
    {
      if(res.headers.location && --redirects)
      {
        _post(res.headers.location, params, callback, redirects);
      }
      else
      {
        callback(data, res.headers, res.statusCode);
      }
    });
  }).on("error", function () {
    callback();
  }).end(encodedData);
}

function _encodePostData(data)
{
  var encoded = querystring.stringify(data);
  return encoded;
}

function _decodePostData(data)
{
  var lines = data.split('\n');
  var result = {};
  for(var l in lines)
  {
    var line = lines[l];
    var colon = line.indexOf(':');
    if(colon === -1)
    {
      continue;
    }
    var key = line.substr(0, line.indexOf(':'));
    var value = line.substr(line.indexOf(':') + 1);
    result[key] = value;
  }

  return result;
}

function _normalizeIdentifier(identifier)
{
  identifier = identifier.replace(/^\s+|\s+$/g, '');
  if(!identifier)
    return null;
  if(identifier.indexOf('xri://') === 0)
  {
    identifier = identifier.substring(6);
  }

  if(/^[(=@\+\$!]/.test(identifier))
  {
    return identifier;
  }

  if(identifier.indexOf('http') === 0)
  {
    return identifier;
  }
  return 'http://' + identifier;
}

function _parseXrds(xrdsUrl, xrdsData)
{
  var services = xrds.parse(xrdsData);
  if(services == null)
  {
    return null;
  }

  var providers = [];
  for(var s in services)
  {
    var service = services[s];
    var provider = {};

    provider.endpoint = service.uri;
    if(/https?:\/\/xri./.test(xrdsUrl))
    {
      provider.claimedIdentifier = service.canonicalIdentifier;
    }
    if(service.type == 'http://specs.openid.net/auth/2.0/signon')
    {
      provider.version = 'http://specs.openid.net/auth/2.0';
      provider.localIdentifier = service.localIdentifier;
    }
    else if(service.type == 'http://specs.openid.net/auth/2.0/server')
    {
      provider.version = 'http://specs.openid.net/auth/2.0';
    }
    else if(service.type == 'http://openid.net/signon/1.0' || 
      service.type == 'http://openid.net/signon/1.1')
    {
      provider.version = service.type;
    }
    else
    {
      continue;
    }
    providers.push(provider);
  }

  return providers;
}

function _matchMetaTag(html)
{
  var metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/ig.exec(html);
  if(!metaTagMatches || metaTagMatches.length < 2)
  {
    return null;
  }

  var contentMatches = /content="(.*?)"/ig.exec(metaTagMatches[1]);
  if(!contentMatches || contentMatches.length < 2)
  {
    return null;
  }

  return contentMatches[1];
}

function _matchLinkTag(html, rel)
{
  var providerLinkMatches = new RegExp('<link\\s+.*?rel="' + rel + '".*?>', 'ig').exec(html);

  if(!providerLinkMatches || providerLinkMatches.length < 1)
  {
    return null;
  }

  var href = /href="(.*?)"/ig.exec(providerLinkMatches[0]);

  if(!href || href.length < 2)
  {
    return null;
  }
  return href[1];
}

_parseHtml = function(htmlUrl, html, callback, hops)
{
  var metaUrl = _matchMetaTag(html);
  if(metaUrl != null)
  {
    return _resolveXri(metaUrl, callback, hops + 1);
  }

  var provider = _matchLinkTag(html, 'openid2.provider');
  if(provider == null)
  {
    provider = _matchLinkTag(html, 'openid.server');
    if(provider == null)
    {
      callback(null);
    }
    else
    {
      var localId = _matchLinkTag(html, 'openid.delegate');
      callback([{ 
        version: 'http://openid.net/signon/1.1',
        endpoint: provider, 
        claimedIdentifier: htmlUrl,
        localIdentifier : localId 
      }]);
    }
  }
  else
  {
    var localId = _matchLinkTag(html, 'openid2.local_id');
    callback([{ 
      version: 'http://specs.openid.net/auth/2.0/signon', 
      endpoint: provider, 
      claimedIdentifier: htmlUrl,
      localIdentifier : localId 
    }]);
  }
}

function _resolveXri(xriUrl, callback, hops)
{
  if(!hops)
  {
    hops = 1;
  }
  else if(hops >= 5)
  {
    return callback(null);
  }

  _get(xriUrl, null, function(data, headers, statusCode)
  {
    if(statusCode != 200)
    {
      return callback(null);
    }

    var xrdsLocation = headers['x-xrds-location'];
    if(_isDef(xrdsLocation))
    {
      _get(xrdsLocation, null, function(data, headers, statusCode)
      {
        if(statusCode != 200 || data == null)
        {
          callback(null);
        }
        else
        {
          callback(_parseXrds(xrdsLocation, data));
        }
      });
    }
    else if(data != null)
    {
      var contentType = headers['content-type'];
      // text/xml is not compliant, but some hosting providers refuse header
      // changes, so text/xml is encountered
      if(contentType.indexOf('application/xrds+xml') === 0 || contentType.indexOf('text/xml') === 0)
      {
        return callback(_parseXrds(xriUrl, data));
      }
      else
      {
        return _resolveHtml(xriUrl, callback, hops + 1, data);
      }
    }
  });
}

function _resolveHtml(identifier, callback, hops, data)
{
  if(!hops)
  {
    hops = 1;
  }
  else if(hops >= 5)
  {
    return callback(null);
  }

  if(data == null)
  {
    _get(identifier, null, function(data, headers, statusCode)
    {
      if(statusCode != 200 || data == null)
      {
        callback(null);
      }
      else
      {
        _parseHtml(identifier, data, callback, hops + 1);
      }
    });
  }
  else
  {
    _parseHtml(identifier, data, callback, hops);
  }

}

openid.discover = function(identifier, callback)
{
  identifier = _normalizeIdentifier(identifier);
  if(!identifier) {
    callback(null);
    return;
  }
  if(identifier.indexOf('http') !== 0)
  {
    // XRDS
    identifier = 'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml';
  }

  // Try XRDS/Yadis discovery

  _resolveXri(identifier, function(data)
  {
    if(data == null)
    {
      // Fallback to HTML discovery
      _resolveHtml(identifier, function(data)
      {
        callback(data);
      });
    }
    else
    {
      callback(data);
    }
  });
}

function _generateDiffieHellmanParameters(algorithm)
{
  var defaultParams = {};
  defaultParams.p = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr';
  defaultParams.g = 'Ag==';

  var p = _fromBase64(defaultParams.p);
  var g = _fromBase64(defaultParams.g);
  var a = null;
  if(algorithm == 'DH-SHA1')
  {
    a = new bigint.BigInteger(20, 1, new bigint.SecureRandom());
  }
  else 
  {
    a = new bigint.BigInteger(32, 1, new bigint.SecureRandom());
  }
  var j = g.modPow(a, p);

  return { p: _toBase64(p),
    g: _toBase64(g), 
    a: _toBase64(a), 
    j: _toBase64(j) };
}

openid.associate = function(provider, callback, algorithm)
{
  var params = _generateAssociationRequestParameters(provider.version, algorithm);
  if(!_isDef(algorithm))
  {
    algorithm = 'DH-SHA256';
  }

  var dh = null;
  if(algorithm.indexOf('no-encryption') === -1)
  {
    dh = _generateDiffieHellmanParameters(algorithm);
    params['openid.dh_modulus'] = dh.p;
    params['openid.dh_gen'] = dh.g;
    params['openid.dh_consumer_public'] = dh.j;
  }

  _post(provider.endpoint, params, function(data, headers, statusCode)
  {
    if(statusCode != 200 || data == null)
    {
      return callback({ 
        error: 'HTTP request failed', 
        error_code: ''  + statusCode, 
        ns: 'http://specs.openid.net/auth/2.0' 
      });
    }

    data = _decodePostData(data);

    if(data.error_code == 'unsupported-type' || !_isDef(data.ns))
    {
      // TODO: Should assert secure channel before
      // allowing unencrypted association?
      // Alternatively, one can drop association and
      // use dumb mode (verify), which is secure
      if(algorithm == 'DH-SHA1' /*&& url.protocol == 'https:'*/)
      {
        openid.associate(provider, callback, 'no-encryption-256');
      }
      else if(algorithm == 'no-encryption-256')
      {
        openid.associate(provider, callback, 'no-encryption');
      }
      else if(algorithm == 'DH-SHA256')
      {
        openid.associate(provider, callback, 'DH-SHA1');
      }
      else
      {
        callback(data);
      }
    }
    else
    {
      var secret = null;

      var hashAlgorithm = algorithm.indexOf('256') !== -1 ? 'sha256' : 'sha1';

      if(algorithm.indexOf('no-encryption') !== -1)
      {
        secret = data.mac_key;
      }
      else
      {
        var serverPublic = _fromBase64(data.dh_server_public);
        var sharedSecret = convert.btwoc(convert.chars_from_hex(
          serverPublic.modPow(_fromBase64(dh.a), _fromBase64(dh.p)).toString(16)));
        var hash = crypto.createHash(hashAlgorithm);
        hash.update(sharedSecret);
        sharedSecret = hash.digest();
        var encMacKey = convert.base64.decode(data.enc_mac_key);
        secret = convert.base64.encode(_xor(encMacKey, sharedSecret));
      }

      openid.saveAssociation(hashAlgorithm,
        data.assoc_handle, secret, data.expires_in * 1);

      callback(data);
    }
  });
}

function _generateAssociationRequestParameters(version, algorithm)
{
  var params = {
    'openid.mode' : 'associate',
  };

  if(version.indexOf('2.0') !== -1)
  {
    params['openid.ns'] = version;
  }

  if(algorithm == 'DH-SHA1')
  {
    params['openid.assoc_type'] = 'HMAC-SHA1';
    params['openid.session_type'] = 'DH-SHA1';
  }
  else if(algorithm == 'no-encryption-256')
  {
    if(version.indexOf('2.0') === -1)
    {
      params['openid.session_type'] = ''; // OpenID 1.1 requires blank
      params['openid.assoc_type'] = 'HMAC-SHA1';
    }
    else
    {
      params['openid.session_type'] = 'no-encryption';
      params['openid.assoc_type'] = 'HMAC-SHA256';
    }
  }
  else if(algorithm == 'no-encryption')
  {
    if(version.indexOf('2.0') !== -1)
    {
      params['openid.session_type'] = 'no-encryption';
    }
    params['openid.assoc_type'] = 'HMAC-SHA1';
  }
  else
  {
    params['openid.assoc_type'] = 'HMAC-SHA256';
    params['openid.session_type'] = 'DH-SHA256';
  }

  return params;
}

openid.authenticate = function(identifier, returnUrl, realm, immediate, callback, extensions)
{
  openid.discover(identifier, function(providers, version)
  {
    if(!providers || providers.length == 0)
    {
      callback(null, "No provider discovered for identity");
    }

    for(var p in providers)
    {
      var provider = providers[p];
      openid.associate(provider, function(answer)
      {
        if(!answer || answer.error)
        {
          callback(null, answer.error);
        }
        
        _requestAuthentication(provider, answer.assoc_handle, returnUrl, realm, immediate, callback, extensions || {});
      });
    }
  });
}

function _requestAuthentication(provider, assoc_handle, returnUrl, realm, immediate, callback, extensions)
{
  var params = {
    'openid.mode' : immediate ? 'checkid_immediate' : 'checkid_setup'
  };

  if(provider.version.indexOf('2.0') !== -1)
  {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
  }

  for(var i in extensions) {
    for(var key in extensions[i].requestParams)
      params[key] = extensions[i].requestParams[key];
  }

  // TODO: 1.1 compatibility
  if(provider.claimedIdentifier)
  {
    params['openid.claimed_id'] = provider.claimedIdentifier;
    if(provider.localIdentifier)
    {
      params['openid.identity'] = provider.localIdentifier;
    }
    else
    {
      params['openid.identity'] = provider.claimedIdentifier;
    }
  }
  else
  {
    params['openid.claimed_id'] = params['openid.identity'] =
      'http://specs.openid.net/auth/2.0/identifier_select';
  }

  if(assoc_handle)
  {
    params['openid.assoc_handle'] = assoc_handle;
  }
  else
  {
    // TODO: This is stateless mode
  }

  if(returnUrl)
  {
    // Value should be missing if RP does not want
    // user to be sent back
    params['openid.return_to'] = returnUrl;
  }

  if(realm)
  {
    params['openid.realm'] = realm;
  }
  else if(!returnUrl)
  {
    throw new Error("No return URL or realm specified");
  }

  callback(_buildUrl(provider.endpoint, params));
}

openid.verifyAssertion = function(requestOrUrl)
{
  var assertionUrl = requestOrUrl;
  if(typeof(requestOrUrl) !== typeof(''))
  {
    assertionUrl = requestOrUrl.url;
  }

  assertionUrl = url.parse(assertionUrl);
  assertionUrl.query = querystring.parse(assertionUrl.query);
  var params = _fixParams(assertionUrl.query);

  var assertionError = _getAssertionError(params);
  if(assertionError)
  {
    return { authenticated: false, error: assertionError };
  }
  if(!_checkValidHandle(params))
  {
    return { authenticated: false, error: 'Association handle has been invalidated' };
  }

  if(!_checkSignature(params))
  {
    return { authenticated: false, error: 'Provider signature is invalid or expired' };
  }

  // make sure to remove already used associations to prevent replay
  openid.removeAssociation(params['openid.assoc_handle']);
  return { authenticated : true , identifier: params['openid.claimed_id'],
    params: params };
}

function _getAssertionError(params)
{
  if(!_isDef(params))
  {
    return 'Assertion request is malformed';
  }
  else if(params['openid.mode'] == 'error')
  {
    return params['openid.error'];
  }
  else if(params['openid.mode'] == 'cancel')
  {
    return 'Authentication cancelled';
  }

  return null;
}

function _checkValidHandle(params)
{
  return !_isDef(params['openid.invalidate_handle']);
}

function _checkSignature(params)
{
  if(!_isDef(params['openid.signed']) ||
    !_isDef(params['openid.sig']))
  {
    return false;
  }

  var association = openid.loadAssociation(params['openid.assoc_handle']);
  if(!association)
  {
    return false;
  }

  var message = '';
  var signedParams = params['openid.signed'].split(',');
  for(var index in signedParams)
  {
    var param = signedParams[index];
    var value = params['openid.' + param];
    if(!_isDef(value))
    {
      return false;
    }
    message += param + ':' + value + '\n';
  }

  var hmac = crypto.createHmac(association.type, _base64ToPlain(association.secret));
  hmac.update(message);
  var ourSignature = hmac.digest('base64');

  return ourSignature == params['openid.sig'];
}

// Recursive parameter lookup for node v0.2.x 
function _fixParams(params) {
  for (var key in params) {
    if (typeof(params[key]) == "object") {
      _fixParams(params[key]);
      for (var childkey in params[key]) {
        params[key + "." + childkey] = params[key][childkey];
      }
      delete params[key];
    }
  }
  return params;
}

/* ----- Extensions ----- */
function _getExtensionAlias(params, ns) {
  for (var k in params)
    if (params[k] == ns)
      return k.replace("openid.ns.", "");
}

/* Simple Registration Extension: http://openid.net/specs/openid-simple-registration-extension-1_1-01.html */
var sreg_keys = ["nickname", "email", "fullname", "dob", "gender", "postcode", "country", "language", "timezone"];
openid.SimpleRegistration = function SimpleRegistration(options) {
  if (options.params) { // parsing the successful result
    var extension = _getExtensionAlias(options.params, "http://openid.net/extensions/sreg/1.1") || "sreg";
    for (var i in sreg_keys) {
      var key = sreg_keys[i];
      if (options.params["openid." + extension + "." + key])
        this[key] = options.params["openid." + extension + "." + key];
    }
  } else { // constructing the params for the auth request
    this.requestParams = {"openid.ns.sreg": "http://openid.net/extensions/sreg/1.1"};
    if (options.policy_url)
      this.requestParams["openid.sreg.policy_url"] = options.policy_url;
    var required = [];
    var optional = [];
    for (var i in sreg_keys) {
      var key = sreg_keys[i];
      if (options[key]) {
        if (options[key] == "required")
          required.push(key);
        else
          optional.push(key);
      }
      if (required.length)
        this.requestParams["openid.sreg.required"] = required.join(",");
      if (optional.length)
        this.requestParams["openid.sreg.optional"] = optional.join(",");
    }
  }
}

/* User Interface Extension: http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html */
openid.UserInterface = function UserInterface(options) {
  if (typeof(options) != "object")
    options = {mode: options || "popup"};
  this.requestParams = {"openid.ns.ui": "http://specs.openid.net/extensions/ui/1.0"};
  for (var k in options) {
    this.requestParams["openid.ui." + k] = options[k];
  }
}

/* Attribute Exchange Extension: http://openid.net/specs/openid-attribute-exchange-1_0.html */
/* also see http://www.axschema.org/types/ and http://code.google.com/intl/de-DE/apis/accounts/docs/OpenID.html#Parameters */
// TODO: count handling
var attributeMapping = {
    "http://axschema.org/contact/country/home": "country"
  , "http://axschema.org/contact/email": "email"
  , "http://axschema.org/namePerson/first": "firstname"
  , "http://axschema.org/pref/language": "language"
  , "http://axschema.org/namePerson/last": "lastname"
  // the following are not in the google document:
  , "http://axschema.org/namePerson/friendly": "nickname"
  , "http://axschema.org/namePerson": "fullname"
};
openid.AttributeExchange = function AttributeExchange(options) {
  if (options.params) { // parsing the successful result
    var extension = _getExtensionAlias(options.params, "http://openid.net/srv/ax/1.0") || "ax";
    var regex = new RegExp("^openid\\." + extension + "\\.(value|type)\\.(\\w+)$");
    var aliases = {};
    var values = {};
    for (var k in options.params) {
      var matches = k.match(regex);
      if (!matches)
        continue;
      if (matches[1] == "type")
        aliases[options.params[k]] = matches[2];
      else
        values[matches[2]] = options.params[k];
    }
    for (var ns in aliases) {
      if (aliases[ns] in values)
        this[ns] = values[aliases[ns]];
    }
  } else { // constructing the params for the auth request
    this.requestParams = {"openid.ns.ax": "http://openid.net/srv/ax/1.0",
      "openid.ax.mode" : "fetch_request"};
    var required = [];
    var optional = [];
    for (var ns in options) {
      if (options[ns] == "required")
        required.push(ns);
      else
        optional.push(ns);
    }
    var self = this;
    required = required.map(function (ns, i) {
      var attr = attributeMapping[ns] || "req" + i;
      self.requestParams["openid.ax.type." + attr] = ns;
      return attr;
    });
    optional = optional.map(function (ns, i) {
      var attr = attributeMapping[ns] || "opt" + i;
      self.requestParams["openid.ax.type." + attr] = ns;
      return attr;
    });
    if (required.length)
      this.requestParams["openid.ax.required"] = required.join(",");
    if (optional.length)
      this.requestParams["openid.ax.if_available"] = optional.join(",");
  }
}
