/* A simple XRDS and Yadis parser written for OpenID for node.js
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
 *  
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- 
 * vim: set sw=2 ts=2 et tw=80 : 
 */

var libxmljs = require("libxmljs");

exports.parse  = function(data)
{
  function xPathTextOrNull(el, path)
  {
    var child = el.get(path);
    return child ? child.text() : null;
  }

  var xml = libxmljs.parseXml(data);
  var services = [];

  xml.root().find('//*[name()=\'Service\']').forEach(function(service)
  {
    var uri = xPathTextOrNull(service, '//*[name()=\'URI\']');
    if (!uri)
      return;

    var priorityAttr = service.attr('priority');
    var priority = priorityAttr ? parseInt(priorityAttr.value()) : 0;

    var id = (xPathTextOrNull(service, '//*[name()=\'LocalID\']') ||
              xPathTextOrNull(service, '//*[name()=\'CanonicalID\']'));

    var delegate = xPathTextOrNull(service, '//*[name()=\'Delegate\']');

    service.find('//*[name()=\'Type\']').forEach(function(type) {
      var object = {
        type: type.text(),
        priority: priority,
        uri: uri,
      };

      if (id) object.id = id;
      if (delegate) object.delegate = delegate;

      services.push(object);
    });
  });

  services.sort(function(a, b) 
  { 
    return a.priority < b.priority 
      ? -1 
      : (a.priority == b.priority ? 0 : 1);
  });

  return services;
}

