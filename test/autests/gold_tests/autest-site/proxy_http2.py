'''
Implement HTTP/2 proxy behavior in Python.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


# The below was initially copied from:
# https://github.com/python-hyper/hyper-h2/blob/e0a3e2eb5449b78ab811f32b7672bfd4e1033cf0/examples/eventlet/eventlet-server.py
#
# The license is the permissive MIT License
# https://github.com/python-hyper/hyper-h2/blob/61ee6f5d588598e36f6d1a3302c8ce2a4ea75dec/LICENSE
#
# I copy the LICENSE file content here in case the above link fails in the future:
#
# -------------
# The MIT License (MIT)
#
# Copyright (c) 2015-2016 Cory Benfield and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# -------------


import sys
import ssl
import http.client
import urllib.parse
import threading
import traceback
import re

from proxy_http1 import ProxyRequestHandler

import collections
import eventlet
from eventlet.green.OpenSSL import SSL, crypto
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived


class Http2ConnectionManager(object):
    timeout = 5
    """
    An object that manages a single HTTP/2 connection.
    """
    def __init__(self, sock):
        config = H2Configuration(client_side=False, validate_inbound_headers=False)
        self.tls = threading.local()
        self.tls.conns = {}
        self.sock = sock
        self.conn = H2Connection(config=config)

    def run_forever(self):
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

        while True:
            data = self.sock.recv(65535)
            if not data:
                break

            events = self.conn.receive_data(data)

            data = b''
            for event in events:
                if isinstance(event, DataReceived):
                    data += event.data

            for event in events:
                if isinstance(event, RequestReceived):
                    self.request_received(event.headers, data, event.stream_id)

            self.sock.sendall(self.conn.data_to_send())

    @staticmethod
    def convert_headers_to_http1(headers):
        """
        Remove the ':...' headers.
        """
        headers_dict = {}
        for key, value in headers.items():
            if key[0] == ':':
                continue
            headers_dict.update({key: value})
        return headers_dict

    def request_received(self, request_headers, req_body, stream_id):
        request_headers = collections.OrderedDict(request_headers)

        scheme = request_headers[':scheme']
        replay_server = "127.0.0.1:{}".format(self.server_port)
        method = request_headers[':method']
        path = request_headers[':path']

        try:
            origin = (scheme, replay_server)
            if origin not in self.tls.conns:
                if scheme == 'https':
                    gcontext = ssl.SSLContext()
                    self.tls.conns[origin] = http.client.HTTPSConnection(
                            replay_server, timeout=self.timeout, context=gcontext, cert_file=self.cert_file)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(replay_server, timeout=self.timeout)
            conn = self.tls.conns[origin]
            http1_headers = self.convert_headers_to_http1(request_headers)
            conn.request(method, path, req_body, http1_headers)
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            response_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.conn.send_headers(stream_id, ((':status', '502')), end_stream=True)
            print("Connection to '{}' initiated with request to '{}://{}{}' failed: {}".format(
                replay_server, scheme, request_headers.get(':authority', ''), path, e))
            traceback.print_exc(file=sys.stdout)
            return

        setattr(res, 'headers', ProxyRequestHandler.filter_headers(res.headers))

        response_headers = (
            (':status', str(res.status)),
        )
        for k, v in res.headers.items():
            response_headers += ((k, v),)
        self.print_info(request_headers, req_body, res.headers, response_body, res.status, res.reason)
        self.conn.send_headers(stream_id, response_headers)
        self.conn.send_data(stream_id, response_body, end_stream=True)

    def print_info(self, request_headers, req_body, response_headers, res_body,
                   response_status, response_reason):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urllib.parse.parse_qsl(s, keep_blank_values=True))

        print("==== REQUEST HEADERS ====\n")
        for k, v in request_headers.items():
            print("{}: {}".format(k, v))

        u = urllib.parse.urlsplit(request_headers[':path'])
        if u.query:
            query_text = parse_qsl(u.query)
            print("==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = request_headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print("==== COOKIE ====\n%s\n" % cookie)

        auth = request_headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print("==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            print("==== REQUEST BODY ====\n%s\n" % req_body)

        status_line = "%d %s\n" % (response_status, response_reason)
        print(status_line)
        print("==== RESPONSE HEADERS ====\n%s\n" % response_headers)
        cookies = response_headers['Set-Cookie']
        if cookies:
            cookies = '\n'.join(cookies)
            print("==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            print("==== RESPONSE BODY ====\n%s\n" % res_body)


def alpn_callback(conn, protos):
    if b'h2' in protos:
        return b'h2'

    raise RuntimeError("No acceptable protocol offered!")


def npn_advertise_cb(conn):
    return [b'h2']


def configure_http2_server(listen_port, server_port, https_pem):
    # Let's set up SSL. This is a lot of work in PyOpenSSL.
    options = (
        SSL.OP_NO_COMPRESSION |
        SSL.OP_NO_SSLv2 |
        SSL.OP_NO_SSLv3 |
        SSL.OP_NO_TLSv1 |
        SSL.OP_NO_TLSv1_1
    )
    # Keep things TSL1_2 and non-ECDH in case tester wants to decrypt the traffic
    # in wireshark with the pem key.
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    context.set_options(options)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    context.use_privatekey_file(https_pem)
    context.use_certificate_file(https_pem)
    context.set_npn_advertise_callback(npn_advertise_cb)
    context.set_alpn_select_callback(alpn_callback)
    context.set_cipher_list(
        "RSA+AESGCM"
    )
    context.set_tmp_ecdh(crypto.get_elliptic_curve(u'prime256v1'))

    server = eventlet.listen(('0.0.0.0', listen_port))
    server = SSL.Connection(context, server)
    print("Serving HTTP/2 Proxy on {}:{} with pem '{}', forwarding to {}:{}".format(
        "127.0.0.1", listen_port, https_pem, "127.0.0.1", server_port))
    pool = eventlet.GreenPool()

    while True:
        try:
            new_sock, _ = server.accept()
            manager = Http2ConnectionManager(new_sock)
            manager.server_port = server_port
            manager.cert_file = https_pem
            pool.spawn_n(manager.run_forever)
        except (SystemExit, KeyboardInterrupt):
            break