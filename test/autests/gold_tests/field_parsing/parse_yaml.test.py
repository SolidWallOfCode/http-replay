'''
Verify correct parsing of YAML replay files.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct parsing of a YAML replay files.
'''

#
# Test 1: Verify correct behavior with a YAML-specified replay file.
#
r = Test.AddTestRun("Verify parsing of a YAML-specified replay file")
client = r.AddClientProcess("client1", "replay_files/yaml_specified",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/yaml_specified",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)


proxy.Streams.stdout = "gold/yaml_specified_proxy.gold"
client.Streams.stdout = "gold/yaml_specified_client.gold"
server.Streams.stdout = "gold/yaml_specified_server.gold"
