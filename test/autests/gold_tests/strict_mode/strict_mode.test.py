'''
Verify strict mode functionality.
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
Verify strict mode functionality.
'''

#
# Test 1: Verify there are no warnings when the fields match.
#
r = Test.AddTestRun("Verify strict mode is silent when the fields match.")
client = r.AddClientProcess("client1", "replay_files/fields_match",
                            http_ports=[8080], other_args="--verbose diag --strict")
server = r.AddServerProcess("server1", "replay_files/fields_match",
                            http_ports=[8081], other_args="--verbose diag --strict")
proxy = r.AddProxyProcess("proxy1", listen_port=8080, server_port=8081)

proxy.Streams.stdout = "gold/fields_match_proxy.gold"

client.Streams.stdout = Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

#
# Test 2: Verify there are warnings when the fields don't match.
#
r = Test.AddTestRun("Verify strict mode warns when the fields don't match")
client = r.AddClientProcess("client2", "replay_files/fields_differ",
                            http_ports=[8082], other_args="--verbose diag --strict")
server = r.AddServerProcess("server2", "replay_files/fields_differ",
                            http_ports=[8083], other_args="--verbose diag --strict")
proxy = r.AddProxyProcess("proxy2", listen_port=8082, server_port=8083)

proxy.Streams.stdout = "gold/fields_differ_proxy.gold"

client.Streams.stdout = Testers.ContainsExpression(
        'Violation: Absent. Key: "x-thisresponseheaderwontexist", Correct Value: "ThereforeTheClientShouldWarn',
        "There should be a warning about the missing response header")

server.Streams.stdout = Testers.ContainsExpression(
        'Violation: Absent. Key: "x-thisrequestheaderwontexist", Correct Value: "ThereforeTheServerShouldWarn',
        "There should be a warning about the missing proxy request header.")
