'''
Verify basic HTTPS functionality.
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
Verify basic HTTPS functionality.
'''

r = Test.AddTestRun("Verify processing of a simple HTTPS transaction")
client = r.AddClientProcess("client1", "replay_files/single_transaction", https_ports=[4443], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/single_transaction", https_ports=[4444], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=4443, server_port=4444, use_ssl=True)

proxy.Streams.stdout = "gold/single_transaction_proxy.gold"

client.Streams.stdout = "gold/single_transaction_client.gold"
client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = "gold/single_transaction_server.gold"
server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
