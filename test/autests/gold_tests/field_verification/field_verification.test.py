'''
Verify basic HTTP/1.x functionality.
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


Test.Summary = '''
Verify correct field verification behavior.
'''

r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client", "http_replay_file", http_ports=[8080], other_args="--verbose diag")
server = r.AddServerProcess("server", "http_replay_file", http_ports=[8081], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy", listen_port=8080, server_port=8081)

# Verify a success and failure of each validation in the request.
server.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "x-cdn"',
        'Validation should be happy that the proxy removed X-CDN.')
server.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "content-type", Value: "application/octet-stream"',
        'Validation should complain that "content-type" is present')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "content-length", Value: "399"',
        'Validation should be happy that "content-length" is present.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "yahooremoteip", Value: "10.10.10.4"',
        'Validation should be happy that "YahooRemoteIP" is present even though its value differs.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "client-ip"',
        'Validation should complain that "client-ip" is misssing')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "y-rid", Value: "bvr4v55e8oqb8"',
        'Validation should be happy that "y-rid" has the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "host", Correct Value: "data.flurry.com", Actual Value: "test.flurry.com"',
        'Validation should complain that the "host" value differs from the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "x-test-case", Correct Value: "CASEmatters", Actual Value: "caseMATTERS"',
        'Equals validation must be case-sensitive.')

# Verify a success and failure of each validation in the response.
client.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "x-content-type-options"',
        'Validation should be happy that the proxy removed X-Content-Type-Options.')
client.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "x-xss-protection", Value: "1; mode=block"',
        'Validation should complain that "X-XSS-Protection" is present')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "content-length", Value: "0"',
        'Validation should be happy that "content-length" is present.')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "age", Value: "4"',
        'Validation should be happy that "Age" is present even though its value differs.')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "x-request-id"',
        'Validation should complain that "x-request-id" is misssing')
client.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "date", Value: "Sat, 16 Mar 2019 03:11:36 GMT"',
        'Validation should be happy that "date" has the expected value.')
client.Streams.stdout += Testers.ContainsExpression(
        ('Equals Violation: Different. Key: "x-testheader", '
            'Correct Value: "from_proxy_response", Actual Value: "from_server_response"'),
        'Validation should complain that the "x-testheader" value differs from the expected value.')
