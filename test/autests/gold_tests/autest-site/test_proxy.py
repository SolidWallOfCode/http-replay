'''
Implement proxy behavior in Python.
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


import argparse
import os

import proxy_http1
import proxy_http2


def parse_args():
    parser = argparse.ArgumentParser(
            description='Implement a simple HTTP proxy which simply forwards transactions.')
    parser.add_argument('--listen-port', metavar='listen_port', type=int,
                        help='The port on which to listen')
    parser.add_argument('--server-port', metavar='server_port', type=int,
                        help='The port on which to connect to the server')
    parser.add_argument('--https-pem', metavar='https_pem', type=str, default=None,
                        help='The file with the cert and key to use for the '
                        'proxy https connection from the client')
    parser.add_argument('--http2_to_1', action="store_true",
                        help='Listen for HTTP/2 connections but talk HTTP/1 to the server.')

    args = parser.parse_args()

    if args.https_pem:
        if not os.path.isfile(args.https_pem):
            raise argparse.ArgumentTypeError(
                    "--https-pem argument is not a file: {}".format(args.https_pem))
    return args


def main():
    args = parse_args()

    if args.http2_to_1:
        proxy_http2.configure_http2_server(args.listen_port, args.server_port, args.https_pem)
    else:
        proxy_http1.configure_http1_server(
                proxy_http1.ProxyRequestHandler, proxy_http1.ThreadingHTTPServer,
                "HTTP/1.1", args.listen_port, args.server_port, args.https_pem)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
    main()
