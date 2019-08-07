/** @file

    Unit tests for HttpReplay.h.

    @section license License

    Licensed to the Apache Software Foundation (ASF) under one or more contributor license
    agreements.  See the NOTICE file distributed with this work for additional information regarding
    copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
    (the "License"); you may not use this file except in compliance with the License.  You may
    obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software distributed under the
    License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
    express or implied. See the License for the specific language governing permissions and
    limitations under the License.
 */

#include "core/HttpReplay.h"
#include "catch.hpp"

// Other parts of new code involve Info calls and reliance on these functions,
// so instead are tested by the test cases in the json folder
TEST_CASE("RuleCheck and Child Classes", "[RCaCC]")
{
  swoc::TextView empty_name;
  swoc::TextView test_name("test");
  RuleCheck::options_init();

  // empty names are not defined, so not tested
  // data field in present and absent is supported but not noted
  YAML::Node yaml_present = YAML::Load("[\"test\", \"e\", \"present\"]");
  YAML::Node yaml_absent = YAML::Load("[\"test\", null, \"absent\"]");
  YAML::Node yaml_equals_not_blank = YAML::Load("[\"test\", \"test\", \"equals\"]");
  YAML::Node yaml_equals_blank = YAML::Load("[\"test\", \"\", \"equals\"]");

  std::shared_ptr<RuleCheck> present_check = RuleCheck::find(yaml_present, test_name);
  std::shared_ptr<RuleCheck> absent_check = RuleCheck::find(yaml_absent, test_name);
  std::shared_ptr<RuleCheck> equals_check_not_blank = RuleCheck::find(yaml_equals_not_blank, test_name);
  std::shared_ptr<RuleCheck> equals_check_blank = RuleCheck::find(yaml_equals_blank, test_name);

  REQUIRE(!present_check->test(empty_name, empty_name));
  REQUIRE(!present_check->test(empty_name, non_empty_name));
  REQUIRE(present_check->test(non_empty_name, empty_name));
  REQUIRE(present_check->test(non_empty_name, non_empty_name));

  REQUIRE(absent_check->test(empty_name, empty_name));
  REQUIRE(absent_check->test(empty_name, non_empty_name));
  REQUIRE(!absent_check->test(non_empty_name, empty_name));
  REQUIRE(!absent_check->test(non_empty_name, non_empty_name));

  REQUIRE(!equals_check_not_blank->test(empty_name, empty_name));
  REQUIRE(!equals_check_not_blank->test(empty_name, non_empty_name));
  REQUIRE(!equals_check_not_blank->test(non_empty_name, empty_name));
  REQUIRE(equals_check_not_blank->test(non_empty_name, non_empty_name));

  REQUIRE(!equals_check_blank->test(empty_name, empty_name));
  REQUIRE(!equals_check_blank->test(empty_name, non_empty_name));
  REQUIRE(equals_check_blank->test(non_empty_name, empty_name));
  REQUIRE(!equals_check_blank->test(non_empty_name, non_empty_name));
}
