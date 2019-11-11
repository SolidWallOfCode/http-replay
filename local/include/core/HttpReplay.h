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
#include <unordered_set>

#include <condition_variable>
#include <deque>
#include <memory>
#include <openssl/ssl.h>
#include <thread>
#include <unistd.h>

#include "yaml-cpp/yaml.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/ext/HashFNV.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"

// Definitions of keys in the CONFIG files.
// These need to be @c std::string or the node look up will construct a @c
// std::string.
static const std::string YAML_META_KEY{"meta"};
static const std::string YAML_GLOBALS_KEY{"global-field-rules"};
static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_SSN_PROTOCOL_KEY{"protocol"};
static const std::string YAML_SSN_START_KEY{"connection-time"};
static const std::string YAML_SSN_TLS_KEY{"tls"};
static const std::string YAML_SSN_TLS_CLIENT_SNI_KEY{"client-sni"};
static const std::string YAML_SSN_TLS_PROXY_SNI_KEY{"proxy-sni"};
static const std::string YAML_TXN_KEY{"transactions"};
static const std::string YAML_CLIENT_REQ_KEY{"client-request"};
static const std::string YAML_PROXY_REQ_KEY{"proxy-request"};
static const std::string YAML_SERVER_RSP_KEY{"server-response"};
static const std::string YAML_PROXY_RSP_KEY{"proxy-response"};
static const std::string YAML_HDR_KEY{"headers"};
static const std::string YAML_FIELDS_KEY{"fields"};
static const std::string YAML_HTTP_VERSION_KEY{"version"};
static const std::string YAML_HTTP_STATUS_KEY{"status"};
static const std::string YAML_HTTP_REASON_KEY{"reason"};
static const std::string YAML_HTTP_METHOD_KEY{"method"};
static const std::string YAML_HTTP_URL_KEY{"url"};
static const std::string YAML_CONTENT_KEY{"content"};
static const std::string YAML_CONTENT_LENGTH_KEY{"size"};
static const std::string YAML_CONTENT_DATA_KEY{"data"};
static const std::string YAML_CONTENT_ENCODING_KEY{"encoding"};
static const std::string YAML_CONTENT_TRANSFER_KEY{"transfer"};

static constexpr size_t YAML_RULE_NAME_KEY{0};
static constexpr size_t YAML_RULE_DATA_KEY{1};
static constexpr size_t YAML_RULE_TYPE_KEY{2};

static const std::string YAML_RULE_EQUALS{"equal"};
static const std::string YAML_RULE_PRESENCE{"present"};
static const std::string YAML_RULE_ABSENCE{"absent"};

static constexpr size_t MAX_HDR_SIZE = 131072; // Max our ATS is configured for
static constexpr size_t MAX_DRAIN_BUFFER_SIZE = 1 << 20;
/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

extern bool Verbose;

class HttpHeader;

/**
 * @brief Configure the process to block SIGPIPE.
 *
 * Unless we block SIGPIPE, the process abruptly stops if SSL_write triggers
 * the signal if the peer drops the connection before we write to the socket.
 * This results in an abrupt termination of the process. SSL_write will return
 * a -1 in these circumstances if the SIGPIPE doesn't interrupt it, so even
 * with the signal blocked we will still report the issue and continue
 * gracefully if SIGPIPE is raised under these circumstances.
 */
void block_sigpipe();

namespace swoc {
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       HttpHeader const &h);
}

struct Hash {
  swoc::Hash64FNV1a::value_type operator()(swoc::TextView view) const {
    return swoc::Hash64FNV1a{}.hash_immediate(
        swoc::transform_view_of(&tolower, view));
  }
  bool operator()(swoc::TextView const &lhs, swoc::TextView const &rhs) const {
    return 0 == strcasecmp(lhs, rhs);
  }
};

class RuleCheck {
  /// References the make_* functions below.
  using RuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, swoc::TextView)>;
  using RuleOptions =
      std::unordered_map<swoc::TextView, RuleFunction, Hash, Hash>;

  static RuleOptions
      options; ///< Returns function to construct a RuleCheck child class for a
               ///< given rule type ("equals", "presence", or "absence")

protected:
  swoc::TextView
      _name; ///< All rules have a name of the field that needs to be checked

public:
  virtual ~RuleCheck() {}

  /** Initialize options with std::functions for creating RuleChecks.
   *
   */
  static void options_init();

  /** Generate @a RuleCheck with @a node with factory pattern.
   *
   * @param node YAML Array node with (in order) the name of the field, data for
   * the field (null if not necessary), and rule for the field (equals, absence,
   * or presence)
   * @param name TextView holding the name of the field (redundant with above so
   * that localization is not performed twice when making TextViews)
   * @return A pointer to the RuleCheck instance generated, holding a key (and
   * potentially value) TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> find(const YAML::Node &node,
                                         swoc::TextView name);

  /** Generate @a EqualityCheck, invoked by the factory function when the
   * "equals" flag is present.
   *
   * @param node TextView holding the name of the target field
   * @param name TextView holding the associated value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the EqualityCheck instance generated, holding key and
   * value TextViews for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_equality(swoc::TextView name,
                                                  swoc::TextView value);

  /** Generate @a PresenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView (unused) in order to have the same signature as
   * make_equality
   * @return A pointer to the Presence instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_presence(swoc::TextView name,
                                                  swoc::TextView value);

  /** Generate @a AbsenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView (unused) in order to have the same signature as
   * make_equality
   * @return A pointer to the AbsenceCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_absence(swoc::TextView name,
                                                 swoc::TextView value);

  /** Pure virtual function to test whether the input name and value fulfill the
   * rules for the test
   *
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView holding the value of the target field (null if not
   * found)
   * @return Whether the check was successful or not
   */
  virtual bool test(swoc::TextView name, swoc::TextView value) const = 0;
};

class EqualityCheck : public RuleCheck {
  swoc::TextView _value; ///< Only EqualityChecks require value comparisons.

public:
  ~EqualityCheck() {}

  /** Construct @a EqualityCheck with a given name and value.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView holding the associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, swoc::TextView value);

  /** Test whether the name and value both match the expected name and value.
   * Reports errors in verbose mode.
   *
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView holding the value of the target field (null if not
   * found)
   * @return Whether the check was successful or not
   */
  virtual bool test(swoc::TextView name, swoc::TextView value) const override;
};

class PresenceCheck : public RuleCheck {
public:
  /** Construct @a PresenceCheck with a given name.
   *
   * @param name TextView holding the name of the target field
   */
  PresenceCheck(swoc::TextView name);

  /** Test whether the name matches the expected name. Reports errors in verbose
   * mode.
   *
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView (unused) holding the value of the target field (null
   * if not found)
   * @return Whether the check was successful or not
   */
  virtual bool test(swoc::TextView name, swoc::TextView value) const override;
};

class AbsenceCheck : public RuleCheck {
public:
  /** Construct @a AbsenceCheck with a given name.
   *
   * @param name TextView holding the name of the target field
   */
  AbsenceCheck(swoc::TextView name);

  /** Test whether the name is null (does not match the expected name). Reports
   * errors in verbose mode.
   *
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView (unused) holding the value of the target field (null
   * if not found)
   * @return Whether the check was successful or not
   */
  virtual bool test(swoc::TextView name, swoc::TextView value) const override;
};

class HttpFields {
  /// std::unordered_map that returns RuleChecks for given field names
  using Rules = std::unordered_map<swoc::TextView, std::shared_ptr<RuleCheck>,
                                   Hash, Hash>;
  using Fields = std::unordered_map<swoc::TextView, std::string, Hash, Hash>;

public:
  Rules _rules;   ///< Maps field names to functors.
  Fields _fields; ///< Maps field names to values.

  /** Parse a node holding as an attribute an individual field array of rules.
   * Used instead of parse_rules on nodes like global_rules_node. Calls
   * parse_rules.
   *
   * @param node YAML Node with Fields attribute holding array of rules
   * @return swoc::Errata holding any encountered errors
   */
  swoc::Errata parse_fields_node(YAML::Node const &node);

  /** Parse an individual array of fields and rules.
   *
   * @param node Array of fields and rules in YAML node format
   * @return swoc::Errata holding any encountered errors
   */
  swoc::Errata parse_fields_rules(YAML::Node const &node);

  friend class HttpHeader;
};

struct VerificationConfig {
  HttpFields *txn_rules;
};

class HttpHeader {
  using self_type = HttpHeader;
  using TextView = swoc::TextView;

  //  using NameSet = std::unordered_set<TextView, std::hash<std::string_view>>;

  using NameSet = std::unordered_set<swoc::TextView, Hash, Hash>;

public:
  /// Parsing results.
  enum ParseResult {
    PARSE_OK,        ///< Parse finished sucessfully.
    PARSE_ERROR,     ///< Invalid data.
    PARSE_INCOMPLETE ///< Parsing not complete.
  };

  /// Important header fields.
  /// @{
  static TextView FIELD_CONTENT_LENGTH;
  static TextView FIELD_TRANSFER_ENCODING;
  /// @}

  /// Mark which status codes have no content by default.
  static std::bitset<600> STATUS_NO_CONTENT;

  HttpHeader() = default;
  HttpHeader(self_type const &) = delete;
  HttpHeader(self_type &&that) = default;
  self_type &operator=(self_type &&that) = default;

  /** Read and parse a header.
   *
   * @param reader [in,out] Data source.
   * @param w [in,out] Read buffer.
   * @return The size of the parsed header, or errors.
   *
   * Because the reading can overrun the header, the overrun must be made
   * available to the caller.
   * @a w is updated to mark all data read (via @c w.size() ). The return value
   * is the size of the header - data past that is the overrun.
   *
   * @note The reader may end up with a closed socket if the socket closes while
   * reading. This must be checked by the caller by calling @c
   * reader.is_closed().
   */
  // swoc::Rv<ssize_t> read_header(Stream &reader, swoc::FixedBufferWriter &w);

  /** Write the body to @a fd.
   *
   * @param fd Outpuf file.
   * @return Errors, if any.
   *
   * This synthesizes the content based on values in the header.
   */
  // swoc::Errata transmit_body(Stream &stream) const;

  /** Drain the content.
   *
   * @param fd [in,out]File to read. This is changed to -1 if closed while
   * draining.
   * @param initial Initial part of the body.
   * @return Errors, if any.
   *
   * If the return is an error, @a fd should be closed. It can be the case @a fd
   * is closed without an error, @a fd must be checked after the call to detect
   * this.
   *
   * @a initial is needed for cases where part of the content is captured while
   * trying to read the header.
   */
  // swoc::Errata drain_body(Stream &stream, TextView initial) const;

  swoc::Errata load(YAML::Node const &node);

  swoc::Rv<ParseResult> parse_request(TextView data);
  swoc::Rv<ParseResult> parse_response(TextView data);

  swoc::Errata update_content_length(TextView method);
  swoc::Errata update_transfer_encoding();

  swoc::Errata serialize(swoc::BufferWriter &w) const;

  std::string make_key();

  /** Iterate over the rules and check that the fields are in line using the
   * stored RuleChecks, and report any errors.
   *
   * @param rules_ HeaderRules to iterate over, contains RuleCheck objects
   * @return Whether any rules were violated
   */
  bool verify_headers(const HttpFields &rules_) const;

  unsigned _status = 0;
  TextView _reason;
  /// If @a content_size is valid but not @a content_data, synthesize the
  /// content. This is split instead of @c TextView because these get set
  /// independently during load.
  char const *_content_data = nullptr; ///< Literal data for the content.
  size_t _content_size = 0;            ///< Length of the content.
  TextView _method;
  TextView _http_version;
  std::string _url;

  /// Maps field names to functors (rules) and field names to values (fields)
  HttpFields _fields_rules;

  /// Body is chunked.
  unsigned _chunked_p : 1;
  /// No Content-Length - close after sending body.
  unsigned _content_length_p : 1;

  /// Format string to generate a key from a transaction.
  static TextView _key_format;

  /// String localization frozen?
  static bool _frozen;

  static void set_max_content_length(size_t n);

  static void global_init();

  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;

protected:
  class Binding : public swoc::bwf::NameBinding {
    using BufferWriter = swoc::BufferWriter;

  public:
    Binding(HttpHeader const &hdr) : _hdr(hdr) {}
    /** Override of virtual method to provide an implementation.
     *
     * @param w Output.
     * @param spec Format specifier for output.
     * @return @a w
     *
     * This is called from the formatting logic to generate output for a named
     * specifier. Subclasses that need to handle name dispatch differently need
     * only override this method.
     */
    BufferWriter &operator()(BufferWriter &w,
                             const swoc::bwf::Spec &spec) const override;

  protected:
    HttpHeader const &_hdr;
  };

  /** Convert @a name to a localized view.
   *
   * @param name Text to localize.
   * @return The localized view, or @a name if localization is frozen and @a
   * name is not found.
   *
   * @a name will be localized if string localization is not frozen, or @a name
   * is already localized.
   */
public:
  static TextView localize(TextView text);
  static TextView localize(char const *c_str);

protected:
  /// Encoding for input text.
  enum class Encoding {
    TEXT, ///< Plain text, no encoding.
    URI   //< URI encoded.
  };

  /** Convert @a name to a localized view.
   *
   * @param name Text to localize.
   * @param enc Type of decoding to perform before localization.
   * @return The localized view, or @a name if localization is frozen and @a
   * name is not found.
   *
   * @a name will be localized if string localization is not frozen, or @a name
   * is already localized. @a enc specifies the text is encoded and needs to be
   * decoded before localization.
   */
  static TextView localize(TextView text, Encoding enc);

  static NameSet _names;
  static swoc::MemArena _arena;
};

/** A stream reader.
 * This is essentially a wrapper around a socket to support use of @c epoll on the
 * socket. The goal is to enable a read operation that waits for data but
 * returns as soon as any data is available.
 */
class Stream {
public:
  Stream();
  virtual ~Stream();

  int fd() const;
  virtual ssize_t read(swoc::MemSpan<char> span);
  virtual ssize_t write(swoc::TextView data);
  virtual swoc::Errata write(HttpHeader const &hdr);
  virtual swoc::Errata write_body(HttpHeader const &hdr);
  virtual swoc::Errata accept();
  virtual swoc::Errata connect();
  virtual swoc::Rv<ssize_t> read_header(swoc::FixedBufferWriter &w);
  virtual swoc::Errata drain_body(HttpHeader &hdr, swoc::TextView initial);

  virtual swoc::Errata open(int fd);
  bool is_closed() const;
  virtual void close();

protected:
  int get_fd() const;

private:
  int _fd = -1; ///< Socket.
};

inline int Stream::fd() const { return _fd; }
inline bool Stream::is_closed() const { return _fd < 0; }

class TLSStream : public Stream {
public:
  using super_type = Stream;
  virtual ssize_t read(swoc::MemSpan<char> span) override;
  virtual ssize_t write(swoc::TextView data) override;
  TLSStream() = default;
  TLSStream(swoc::TextView const &client_sni) : _client_sni(client_sni) {}
  ~TLSStream() override {
    if (_ssl)
      SSL_free(_ssl);
  }

  void close() override;
  swoc::Errata accept() override;
  swoc::Errata connect() override;
  static swoc::Errata init();
  static swoc::file::path certificate_file;
  static swoc::file::path privatekey_file;

protected:
  SSL *_ssl = nullptr;
  swoc::TextView _client_sni;
  static SSL_CTX *server_ctx;
  static SSL_CTX *client_ctx;
};

class ChunkCodex {
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Data for the chunk in the provided view.
  /// @param offset The offset from the full chunk for @a chunk.
  /// @param size The size of the full chunk.
  /// Because the data provided might not contain the entire chunk, a chunk can
  /// come back piecemeal in the callbacks. The @a offset and @a size specify
  /// where in the actual chunk the particular piece in @a chunk is placed.
  using ChunkCallback =
      std::function<bool(swoc::TextView chunk, size_t offset, size_t size)>;
  enum Result { CONTINUE, DONE, ERROR };

  /** Parse @a data as chunked encoded.
   *
   * @param data Data to parse.
   * @param cb Callback to receive decoded chunks.
   * @return Parsing result.
   *
   * The parsing is designed to be restartable so that data can be passed
   * directly from the socket to this object, without doing any gathering.
   */
  Result parse(swoc::TextView data, ChunkCallback const &cb);

  /** Write @a data to @a fd using chunked encoding.
   *
   * @param fd Output file descriptor.
   * @param data [in,out] Data to write.
   * @param chunk_size Size of chunks.
   * @return A pair of
   *   - The number of bytes written from @a data (not including the chunk
   * encoding).
   *   - An error code, which will be 0 if all data was successfully written.
   */
  std::tuple<ssize_t, std::error_code>
  transmit(Stream &stream, swoc::TextView data, size_t chunk_size = 4096);

protected:
  size_t _size = 0; ///< Size of the current chunking being decoded.
  size_t _off =
      0; ///< Number of bytes in the current chunk already sent to the callback.
  /// Buffer to hold size text in case it falls across @c parse call boundaries.
  swoc::LocalBufferWriter<16> _size_text;

  /// Parsing state.
  enum class State {
    INIT, ///< Initial state, no parsing has occurred.
    SIZE, ///< Parsing the chunk size.
    CR,   ///< Expecting the size terminating CR
    LF,   ///< Expecting the size terminating LF.
    BODY, ///< Inside the chunk body.
    POST_BODY_CR,
    POST_BODY_LF,
    FINAL ///< Terminating (size zero) chunk parsed.
  } _state = State::INIT;
};

// YAML support utilities.
namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              YAML::Mark const &mark) {
  return w.print("line {}", mark.line);
}
} // namespace swoc

/** Protocol class for loading a replay file.
 * The client and server are expected subclass this an provide an
 * implementation.
 */
class ReplayFileHandler {
public:
  VerificationConfig config;

  virtual swoc::Errata file_open(swoc::file::path const &path) {
    _path = path.string();
    return {};
  }
  virtual swoc::Errata file_close() { return {}; }
  virtual swoc::Errata ssn_open(YAML::Node const &node) { return {}; }
  virtual swoc::Errata ssn_close() { return {}; }

  /** Open the transaction node.
   *
   * @param node Transaction node.
   * @return Errors, if any.
   *
   * This is required to do any base validation of the transaction such as
   * verifying required keys.
   */
  virtual swoc::Errata txn_open(YAML::Node const &node) { return {}; }

  virtual swoc::Errata txn_close() { return {}; }
  virtual swoc::Errata client_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata server_response(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_response(YAML::Node const &node) { return {}; }

protected:
  /**
   * @brief The replay file associated with this handler.
   */
  std::string _path;
};

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler);

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads = 10);

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Errata resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView host);

namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              swoc::file::path const &path) {
  return bwformat(w, spec, path.string());
}
} // namespace swoc

template <typename... Args> void Info(swoc::TextView fmt, Args &&... args) {
  if (Verbose) {
    swoc::LocalBufferWriter<1024> w;
    w.print_v(fmt, std::forward_as_tuple(args...));
    if (w.error()) {
      std::string s;
      swoc::bwprint_v(s, fmt, std::forward_as_tuple(args...));
      std::cout << s << std::endl;
      std::cout << s << std::endl;
    } else {
      std::cout << w << std::endl;
    }
  }
}

class ThreadInfo {
public:
  std::thread *_thread = nullptr;
  std::condition_variable _cvar;
  std::mutex _mutex;
  virtual bool data_ready() = 0;
};

// This must be a list so that iterators / pointers to elements do not go stale.
class ThreadPool {
public:
  void wait_for_work(ThreadInfo *info);
  ThreadInfo *get_worker();
  virtual std::thread make_thread(std::thread *) = 0;
  void join_threads();

protected:
  std::list<std::thread> _allThreads;
  // Pool of ready / idle threads.
  std::deque<ThreadInfo *> _threadPool;
  std::condition_variable _threadPoolCvar;
  std::mutex _threadPoolMutex;
  const int max_threads = 2000;
};
