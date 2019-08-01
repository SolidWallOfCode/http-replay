/** @file

  Common data structures and definitions for HTTP replay tools.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one or more contributor
  license agreements. See the NOTICE file distributed with this work for
  additional information regarding copyright ownership.  The ASF licenses this
  file to you under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License.  You may obtain a copy of
  the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations under
  the License.
 */

#pragma once

#include <string>
#include <unordered_map>

#include "yaml-cpp/yaml.h"

#include "swoc/TextView.h"

static const std::string YAML_TRANSCLUDE_KEY{"<<"};

// Structured binding support for nodes. E.g.
// YAML::Node node;
// for ( auto const& [ key, value ] : node ] { ... }
namespace std {
  template<> class tuple_size<YAML::const_iterator::value_type> : public std::integral_constant<size_t, 2> {};
  template<> class tuple_element<0, YAML::const_iterator::value_type> { public: using type = const YAML::Node; };
  template<> class tuple_element<1, YAML::const_iterator::value_type> { public: using type = const YAML::Node; };
  template<> class tuple_size<YAML::iterator::value_type> : public std::integral_constant<size_t, 2> {};
  template<> class tuple_element<0, YAML::iterator::value_type> { public: using type = YAML::Node; };
  template<> class tuple_element<1, YAML::iterator::value_type> { public: using type = YAML::Node; };
} // namespace std

template < size_t IDX > YAML::Node const& get(YAML::const_iterator::value_type const& v);
template <> inline YAML::Node const& get<0>(YAML::const_iterator::value_type const& v) { return v
.first; }
template <> inline YAML::Node const& get<1>(YAML::const_iterator::value_type const& v) { return v
.second; }
template < size_t IDX > YAML::Node & get(YAML::iterator::value_type & v);
template <> inline YAML::Node & get<0>(YAML::iterator::value_type & v) { return v
.first; }
template <> inline YAML::Node & get<1>(YAML::iterator::value_type & v) { return v
.second; }

class YamlTransclude {
public:
  static void transclude_sequence(YAML::Node &node) {
    for (auto && child : node) {
      if (child.IsMap()) {
        transclude_map(child);
      } else if (child.IsSequence()) {
        transclude_sequence(child);
      }
    }
  }

  static void transclude_map(YAML::Node &node) {
    for (auto && [ key, value ] : node) {
      const std::string& name = key.Scalar();
      if (name == YAML_TRANSCLUDE_KEY) {
        if (value.IsMap()) { // If one transcluded map
          flatten_into(node, value);
        } else if (value.IsSequence()) { // If more than one
          for (auto const &seq_node : value) {
            flatten_into(node, seq_node);
          }
        } else {
          exit(1);
          // error
        }
      }
      if (value.IsMap()) {
        transclude_map(value);
      } else if (value.IsSequence()) {
        transclude_sequence(value);
      }
    }
  }

private:
  static void flatten_into(YAML::Node &copy_to, YAML::Node const &copy_from) {
    for (const auto & [ key, value ] : copy_from) {
      const std::string& name = key.Scalar();
      if (!copy_to[name]) {
        copy_to[name] = value;
      }
    }
  }
};
