'''
Verify basic HTTP/1.x functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


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

#
# Test 3: Verify correct behavior with a YAML-specified replay file.
#
r = Test.AddTestRun("Verify HTTP/1 processing of a YAML-specified replay file")
client = r.AddClientProcess("client3", "replay_files/yaml_specified",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server3", "replay_files/yaml_specified",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy3", listen_port=8082, server_port=8083)


proxy.Streams.stdout = "gold/yaml_specified_proxy.gold"
client.Streams.stdout = "gold/yaml_specified_client.gold"
server.Streams.stdout = "gold/yaml_specified_server.gold"


#
# Test 4: Verify correct handling of an empty field.
#
r = Test.AddTestRun("Verify correct handling of an empty header field")
client = r.AddClientProcess("client4", "replay_files/empty_field",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server4", "replay_files/empty_field",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy4", listen_port=8082, server_port=8083)

client.ReturnCode = 1
server.ReturnCode = 1

# Due to the parsing failure, the server will not listen on the port.
# Thus the standard ready criteria will not work.
server.Ready = None

client.Streams.stdout = Testers.ContainsExpression(
        "Field or rule at line .* is not a sequence as required",
        "Verify that we inform the user of the malformed field.")
server.Streams.stdout = Testers.ContainsExpression(
        "Field or rule at line .* is not a sequence as required",
        "Verify that we inform the user of the malformed field.")
