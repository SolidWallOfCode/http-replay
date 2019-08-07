.. Licensed to the Apache Software Foundation (ASF) under one or more contributor license
   agreements.  See the NOTICE file distributed with this work for additional information regarding
   copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with the License.  You may obtain
   a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software distributed under the License
   is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
   or implied.  See the License for the specific language governing permissions and limitations
   under the License.

.. include:: ../common-defs.rst
.. highlight:: cpp
.. default-domain:: cpp

.. _EnvironmentSetup:

*****************
Environment Setup
*****************

The environment used during testing consisted of one replay client, one replay server, one ATS
instance, and one microDNS instance.

The ATS instance was configured with, in ats/etc/trafficserver/ssl_multicert.config,

``dest_ip=* ssl_cert_name=<pem> ssl_key_name=<key>``

Where ''<pem>'' and ''<key>'' refer to certificate and key pair that will be shared between ATS
and the replay server. In ats/etc/trafficserver/remap.config,

``regex_map http://(.*) http://$1:<http port>
regex_map https://(.*) https://$1:<https port>``

With the ports that the replay server will listen for requests on. The following were appended to
ats/etc/trafficserver/records.config:

``CONFIG proxy.config.ssl.server.cert.path STRING <cert folder>
CONFIG proxy.config.ssl.server.private_key.path STRING <key folder>
CONFIG proxy.config.http.server_ports STRING <http port> <http port>:ipv6 <https port>:proto=http:ssl
CONFIG proxy.config.dns.nameservers STRING 127.0.0.1:<dns port>
CONFIG proxy.config.dns.resolv_conf STRING NULL
CONFIG proxy.config.url_remap.remap_required INT 0``

Where ``<cert folder>`` and ``<key folder>`` refer the folders where the same key and certificate
pair that the replay server will use are located, ''<http port>'' and ''<https port>'' refer to the
ports that ATS will listen on (these will be passed to the replay client), and ''<dns port>'' refers
to the port that microDNS will listen on.

microDNS was configured with the following in a ``microdnsconf.json`` file:

``{
      "mappings": [],
      "otherwise": ["127.0.0.1"]
}``

It was invoked with ``microdns 127.0.0.1 <dns port> microdnsconf.json``, with ``<dns port>``
referencing the same port set up in the ATS configuration file.

The HTTP Replay server was invoked with ``./replay-server run <test file> --listen 127.0.0.1:<http port> --cert <combined> --listen-https 127.0.0.1:<https port> --verbose``

Where ``<test file>`` is the JSON or YAML replay file, ``<http port>`` and ``<https port>`` reference
the setup in remap.config, and ``<combined>`` references a concatenated version of the same
certificate and key pair set up in records.config and ssl_multicert.config earlier.

For both server and client, the verbose flag shows more detailed error messages, particularly with
header validation.

The HTTP Replay client was invoked with ``./replay-client run <test file> 127.0.0.1:<http port> 127.0.0.1:<https port> --verbose``

Where ``<test file>`` is the same JSON or YAML replay file used by the server, ``<http port>``
and ``<https port>`` reference the setup in records.config (the ports that ATS is listening on),
and ``<combined>`` references a concatenated version of the same certificate and key pair set up
in records.config and ssl_multicert.config earlier.

The "key" flag to the replay server does not refer to cryptographic keys, but instead to the
identifying flag in headers that the server uses to choose how to verify and respond to incoming
requests. It is recommended to omit it from the command line invocation (it defaults to uuid).

Example
=======

Here is a simple example outlining the structure of a replay file. Note the override of the "Host"
field, the arrays of length 2 in the client request and server response, and the arrays of length 3
in the proxy request and response.

.. literalinclude:: ../../json/doc.json
