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

import axios, { AxiosResponse } from "axios";

export async function get(getUrl: string, params?: URLSearchParams, redirects?: number): Promise<AxiosResponse<string>> {
    return axios({
        method: 'GET',
        url: getUrl,
        params,
        maxRedirects: redirects ?? 5,
        responseType: 'text',
        headers: {
            'Accept': 'application/xrds+xml,text/html,text/plain,*/*;q=0.9'
        }
    });
};

export async function post(postUrl: string, data: URLSearchParams, redirects?: number): Promise<AxiosResponse<string>> {
    return axios({
        method: "POST",
        url: postUrl,
        maxRedirects: redirects ?? 5,
        data: data.toString(),
        responseType: 'text',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });
};
