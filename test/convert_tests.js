/* OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2016 by Andreas Leidig
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
var crypto = require('crypto');
var convert = require('../lib/convert');

exports.testBase64Decode = function(test)
{
  var input = 'KKn9KPJIg2BncwIgHcKNZCOhflbWniT0NBmv8hB5btQ=';

  test.equal(convert.base64.decode(input), '(©ý(òH`gs Âd#¡~VÖ$ô4¯òynÔ');
  test.done();
};

exports.testBase64Encode = function(test)
{
  var input = '(©ý(òH`gs Âd#¡~VÖ$ô4¯òynÔ';

  test.equal('KKn9KPJIg2BncwIgHcKNZCOhflbWniT0NBmv8hB5btQ=', convert.base64.encode(input));
  test.done();
};

exports.testAnalogToDigestingContext = function(test)
{
  var association = {
    'provider': {
      'endpoint': 'https://openid.stackexchange.com/openid/provider',
      'version': 'http://specs.openid.net/auth/2.0'
    },
    'type': 'sha256',
    'secret': 'uVTA0AVJdK3xZ83Lk2HCMaSKN7vKcSlJNnv0LOZMGGM='
  };
  var message = 'claimed_id:https://openid.stackexchange.com/user/dff03c7f-21ef-46a4-83ed-8ccede2aa294\n' +
    'identity:https://openid.stackexchange.com/user/dff03c7f-21ef-46a4-83ed-8ccede2aa294\n' +
    'assoc_handle:xnzK!IAAAAALp2v5MxrMUEOwexv2Lg0bTt_TLNLJOy29CKSCyW4owQQAAAAFVe6XkaHOnkk9m40eQQcOuS9DpBafp5IOW_BqNMXvXs5r2pqFDT1yIAuUMqQuT9zzOxmzR7_3RHy2oW83u9mFX\n' +
    'op_endpoint:https://openid.stackexchange.com/openid/provider\n' +
    'return_to:http://localhost:17124/auth/openid/callback\n' +
    'response_nonce:2016-09-02T11:38:37ZceGkjmca\n' +
    'ns.sreg:http://openid.net/extensions/sreg/1.1\n' +
    'sreg.email:derleider@web.de\n' +
    'ns.alias3:http://openid.net/srv/ax/1.0\n' +
    'alias3.mode:fetch_response\n' +
    'alias3.type.alias1:http://axschema.org/contact/email\n' +
    'alias3.value.alias1:derleider@web.de\n';

  var decoded = convert.base64.decode(association.secret);

  var hmac = crypto.createHmac(association.type, decoded);
  hmac.update(message, 'utf8');
  
  test.equal(hmac.digest('base64'), 'KKn9KPJIg2BncwIgHcKNZCOhflbWniT0NBmv8hB5btQ=');
  test.done();
};
