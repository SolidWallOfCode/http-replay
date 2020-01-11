'''
Verify basic HTTP/1.x functionality.
'''
# @file
#
# Copyright 2020, Oath Inc.
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct field verification behavior.
'''

r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client", "http_replay_file", http_ports=[8080], other_args="--verbose diag")
server = r.AddServerProcess("server", "http_replay_file", http_ports=[8081], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy", listen_port=8080, server_port=8081)

# Verify a success and failure of each validation in the request.
server.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "x-candy"',
        'Validation should be happy that the proxy removed X-CANDY.')
server.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "content-type", Value: "application/octet-stream"',
        'Validation should complain that "content-type" is present')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "content-length", Value: "399"',
        'Validation should be happy that "content-length" is present.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "exampleremoteip", Value: "10.10.10.4"',
        'Validation should be happy that "ExampleRemoteIP" is present even though its value differs.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "client-ip"',
        'Validation should complain that "client-ip" is misssing')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "x-someid", Value: "21djfk39jfkds"',
        'Validation should be happy that "S-SomeId" has the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "host", Correct Value: "example.com", Actual Value: "test.example.com"',
        'Validation should complain that the "Host" value differs from the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "x-test-case", Correct Value: "CASEmatters", Actual Value: "caseMATTERS"',
        'Equals validation must be case-sensitive.')

# Verify a success and failure of each validation in the response.
client.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "x-newtestheader"',
        'Validation should be happy that the proxy removed X-NewTestHeader.')
client.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "x-shouldexist", Value: "trustme; it=will"',
        'Validation should complain that "X-ShouldExist" is present')
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
