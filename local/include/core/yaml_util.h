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

#include "yaml-cpp/yaml.h"

// Structured binding support for nodes. E.g.
// YAML::Node node;
// for ( auto const& [ key, value ] : node ] { ... }
namespace std {
template <>
class tuple_size<YAML::const_iterator::value_type>
    : public std::integral_constant<size_t, 2> {};
template <> class tuple_element<0, YAML::const_iterator::value_type> {
public:
  using type = const YAML::Node;
};
template <> class tuple_element<1, YAML::const_iterator::value_type> {
public:
  using type = const YAML::Node;
};
template <>
class tuple_size<YAML::iterator::value_type>
    : public std::integral_constant<size_t, 2> {};
template <> class tuple_element<0, YAML::iterator::value_type> {
public:
  using type = YAML::Node;
};
template <> class tuple_element<1, YAML::iterator::value_type> {
public:
  using type = YAML::Node;
};
} // namespace std

template <size_t IDX>
YAML::Node const &get(YAML::const_iterator::value_type const &v);
template <>
inline YAML::Node const &get<0>(YAML::const_iterator::value_type const &v) {
  return v.first;
}
template <>
inline YAML::Node const &get<1>(YAML::const_iterator::value_type const &v) {
  return v.second;
}
template <size_t IDX> YAML::Node &get(YAML::iterator::value_type &v);
template <> inline YAML::Node &get<0>(YAML::iterator::value_type &v) {
  return v.first;
}
template <> inline YAML::Node &get<1>(YAML::iterator::value_type &v) {
  return v.second;
}

/* ------------------------------------------------------------------------------------
 */
static const std::string YAML_MERGE_KEY{"<<"};

YAML::Node yaml_merge(YAML::Node &root) {
  static constexpr auto flatten = [](YAML::Node &dst, YAML::Node &src) -> void {
    if (src.IsMap()) {
      for (auto const &[key, value] : src) {
        // don't need to check for nested merge key, because this function is
        // called only if that's already set in @a dst therefore it won't be
        // copied up from @a src.
        if (!dst[key]) {
          dst[key] = value;
        }
      }
    }
  };

  if (root.IsSequence()) {
    for (auto &&child : root) {
      yaml_merge(child);
    }
  } else if (root.IsMap()) {
    // Do all nested merges first, so the result is iteration order independent.
    for (auto &&[key, value] : root) {
      value = yaml_merge(value);
    }
    // If there's a merge key, merge it in.
    if (auto merge_node{root[YAML_MERGE_KEY]}; merge_node) {
      if (merge_node.IsMap()) {
        flatten(root, merge_node);
      } else if (merge_node.IsSequence()) {
        for (auto &&src : merge_node) {
          flatten(root, src);
        }
      }
      root.remove(YAML_MERGE_KEY);
    }
  }
  return root;
}
/* ------------------------------------------------------------------------------------
 */
