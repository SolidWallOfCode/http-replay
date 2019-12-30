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
Verify basic HTTP/1.x functionality.
'''

#
# Test 1: Verify correct behavior of a single HTTP transaction.
#
r = Test.AddTestRun("Verify HTTP/1 processing of a single HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/single_transaction", http_ports=[8080], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/single_transaction", http_ports=[8081], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8080, server_port=8081)


proxy.Streams.stdout = "gold/single_transaction_proxy.gold"

client.Streams.stdout = "gold/single_transaction_client.gold"
client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = "gold/single_transaction_server.gold"
server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

#
# Test 2: Verify correct behavior of multiple HTTP sessions.
#
r = Test.AddTestRun("Verify HTTP/1 processing of multiple HTTP transactions")
client = r.AddClientProcess("client2", "replay_files/multiple_transactions",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server2", "replay_files/multiple_transactions",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=8082, server_port=8083)


client.Streams.stdout = Testers.ContainsExpression(
        "6 transactions in 4 sessions",
        "Verify that 6 transactions were parsed.")

client.Streams.stdout += Testers.ContainsExpression(
        "Loading 2 replay files.",
        "Verify that 2 replay files were parsesd.")

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = Testers.ContainsExpression(
        "Ready with 6 transactions.",
        "Verify that 6 transactions were parsed.")

server.Streams.stdout += Testers.ContainsExpression(
        "Loading 2 replay files",
        "Verify that 2 replay files were parsed.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")