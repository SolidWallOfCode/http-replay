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

.. _ReplayFiles:

************
Replay Files
************

Synopsis
********

:code:`#include <core/HttpReplay.h>`

Replay files are the input files for the HttpReplay system. They consist of JSON with certain global
properties, as well as a list of sessions, which contain more properties that apply to transactions
listed within each session. Each transaction contains a client request, which represents the request
sent from the client to an Apache Traffic Server instance, the proxy request, representing the
request from the instance to the server, the server response, representing the response from the
server to the ATS instance, and the proxy response, representing the response from the instance to
the client.

The fields of the client request and server response are set beforehand by the maker of the replay
file. The client sends each request in finds in the file, while the server looks up the associated
response for each incoming proxy request and replies with the given fields, and an arbitrary body
of a specified length. The Apache Traffic Server generates the proxy request and response, so
instead of specifying fields, rules for fields are instead specified, which the client or server
will then verify upon receiving a request or response.

Supported rules for fields include equality (checking the value of a certain named field is equal
to a certain string), presence (checking a named field exists at all), and absence (checking a named
field does not exist). Rules for fields can also be applied globally, to all transactions, by
listing them in a "global field rules" list at the beginning of the replay file.

Example
=======

Here is a simple example outlining the structure of a replay file. Note the override of the "Host"
field, the arrays of length 2 in the client request and server response, and the arrays of length 3
in the proxy request and response.

.. literalinclude:: ../../json/doc.json
