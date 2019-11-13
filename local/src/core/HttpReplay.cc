/** @file

  Common implementation for HTTP replay.

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

#include "core/HttpReplay.h"
#include "core/yaml_util.h"

#include <dirent.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <thread>
#include <signal.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

bool Verbose = false;

bool HttpHeader::_frozen = false;
swoc::MemArena HttpHeader::_arena{8000};
HttpHeader::NameSet HttpHeader::_names;
swoc::TextView HttpHeader::_key_format{"{field.uuid}"};
swoc::MemSpan<char> HttpHeader::_content;
swoc::TextView HttpHeader::FIELD_CONTENT_LENGTH;
swoc::TextView HttpHeader::FIELD_TRANSFER_ENCODING;
std::bitset<600> HttpHeader::STATUS_NO_CONTENT;

RuleCheck::RuleOptions RuleCheck::options;

namespace {
[[maybe_unused]] bool INITIALIZED = []() -> bool {
  HttpHeader::global_init();
  return true;
}();
}

swoc::Rv<int> block_sigpipe()
{
  swoc::Rv<int> zret = 0;
  sigset_t set;
  if (sigemptyset(&set)) {
    zret = -1;
    zret.errata().error(R"(Could not empty the signal set: {})", swoc::bwf::Errno{});
  } else if (sigaddset(&set, SIGPIPE)) {
    zret = -1;
    zret.errata().error(R"(Could not add SIGPIPE to the signal set: {})", swoc::bwf::Errno{});
  } else if (pthread_sigmask(SIG_BLOCK, &set, NULL)) {
    zret = -1;
    zret.errata().error(R"(Could not block SIGPIPE: {})", swoc::bwf::Errno{});
  }
  return zret;
}

swoc::Errata configure_logging(const std::string_view verbose_argument)
{
  swoc::Errata errata;
  auto severity_cutoff = swoc::Severity::INFO;
  if (strcasecmp(verbose_argument, "error") == 0) {
    severity_cutoff = swoc::Severity::ERROR;
  } else if (strcasecmp(verbose_argument, "warn") == 0) {
    severity_cutoff = swoc::Severity::WARN;
  } else if (strcasecmp(verbose_argument, "info") == 0) {
    severity_cutoff = swoc::Severity::INFO;
  } else if (strcasecmp(verbose_argument, "diag") == 0) {
    severity_cutoff = swoc::Severity::DIAG;
  } else {
    errata.error("Unrecognized verbosity parameter: {}", verbose_argument);
    return errata;
  }
  errata.diag("Configuring logging at level {}", severity_cutoff);

  swoc::Errata::register_sink(
      [severity_cutoff](Errata const &errata) {
        if (errata.severity() < severity_cutoff) {
          return;
        }
        std::string_view lead;
        for (const auto& annotation : errata) {
          if (annotation.severity() < severity_cutoff) {
            continue;
          }
          std::cout << lead << " [" << static_cast<int>(annotation.severity())
              << "]: " << annotation.text() << std::endl;
          if (lead.size() == 0) {
            lead = "  "_sv;
          }
        }
      });
  return errata;
}

Stream::Stream() {}

Stream::~Stream() { this->close(); }

swoc::Rv<ssize_t> Stream::read(swoc::MemSpan<char> span) {
  swoc::Rv<ssize_t> zret{
    ::read(_fd, span.data(), span.size())};
  if (zret <= 0) {
    this->close();
  }
  return zret;
}

swoc::Rv<ssize_t> TLSStream::read(swoc::MemSpan<char> span) {
  errno = 0;
  swoc::Rv<ssize_t> zret{SSL_read(this->_ssl, span.data(), span.size())};
  const auto ssl_error = (zret <= 0) ? SSL_get_error(_ssl, zret) : 0;

  if ((zret < 0 && ssl_error != SSL_ERROR_WANT_READ)) {
    zret.errata().error(R"(read of {} bytes failed. Bytes read: {}, ssl_err: {}, errno: {})",
            span.size(),
            zret.result(),
            swoc::bwf::SSLError{ssl_error},
            swoc::bwf::Errno{});
    this->close();
  } else if (zret == 0) {
    this->close();
  }
  return zret;
}

swoc::Rv<ssize_t> Stream::write(swoc::TextView view) {
  return ::write(_fd, view.data(), view.size());
}

swoc::Rv<ssize_t> Stream::write(HttpHeader const &hdr) {
  // 1. header.serialize, write it out
  // 2. transmit the body
  swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
  swoc::Rv<ssize_t> zret{-1};

  zret.errata() = hdr.serialize(w);

  if (zret.is_ok()) {
    zret.result() = write(w.view());

    if (zret == w.size()) {
      zret.result() += write_body(hdr);
    } else {
      zret.errata().error(R"(Header write failed with {} of {} bytes written: {}.)",
          zret.result(), w.size(), swoc::bwf::Errno{});
    }
  }
  return zret;
}

swoc::Rv<ssize_t> Stream::read_header(swoc::FixedBufferWriter &w) {
  swoc::Rv<ssize_t> zret{-1};

  zret.errata().diag("Reading header.");
  while (w.remaining() > 0) {
    auto n = read(w.aux_span());
    if (!is_closed()) {
      // Where to start searching for the EOH string.
      size_t start =
          std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
      w.commit(n);
      size_t offset = w.view().substr(start).find(HTTP_EOH);
      if (TextView::npos != offset) {
        zret = start + offset + HTTP_EOH.size();
        break;
      }
    } else {
      if (w.size()) {
        zret.errata().error(
            R"(Connection closed unexpectedly after {} bytes while waiting for header: {}.)",
            w.size(), swoc::bwf::Errno{});
      } else {
        zret = 0; // clean close between transactions.
      }
      break;
    }
  }
  if (zret.is_ok() && zret == -1) {
    zret.errata().error(R"(Header exceeded maximum size {}.)", w.capacity());
  }
  return std::move(zret);
}

swoc::Rv<size_t> Stream::drain_body(HttpHeader const &hdr, swoc::TextView initial) {
  static constexpr size_t UNBOUNDED = std::numeric_limits<size_t>::max();
  swoc::Rv<size_t> body_size = 0; // bytes drained for the content body.
  std::string buff;
  size_t content_length = hdr._content_length_p ? hdr._content_size : UNBOUNDED;
  if (content_length < initial.size()) {
    body_size.errata().error(
        R"(Response overrun: received {} bytes of content, expected {}.)",
        initial.size(), content_length);
    return body_size;
  }

  // If there's a status, and it indicates no body, we're done.
  if (hdr._status && HttpHeader::STATUS_NO_CONTENT[hdr._status] &&
      !hdr._content_length_p && !hdr._chunked_p) {
    return body_size;
  }

  buff.reserve(std::min<size_t>(content_length, MAX_DRAIN_BUFFER_SIZE));

  if (is_closed()) {
    body_size.errata().error(R"(drain_body: stream closed) could not read {} bytes)",
                 content_length);
    return body_size;
  }

  if (hdr._chunked_p) {
    ChunkCodex::ChunkCallback cb{
        [&](TextView block, size_t offset, size_t size) -> bool {
          body_size.result() += block.size();
          return true;
        }};
    ChunkCodex codex;

    auto result = codex.parse(initial, cb);
    while (result == ChunkCodex::CONTINUE && body_size < content_length) {
      auto n{read({buff.data(), std::min<size_t>(content_length - body_size,
                                                 MAX_DRAIN_BUFFER_SIZE)})};
      if (is_closed()) {
        if (content_length == UNBOUNDED) {
          // Is this an error? It's chunked, so an actual close seems unexpected
          // - should have parsed the empty chunk.
          body_size.errata().info("Connection closed on unbounded chunked-encoded body.");
          result = ChunkCodex::DONE;
        } else {
          body_size.errata().error(
              R"(Response underrun: received {} bytes of content, expected {}, when file closed because {}.)",
              body_size.result(), content_length, swoc::bwf::Errno{});
        }
        break;
      } else {
        result = codex.parse(TextView(buff.data(), n), cb);
      }
    }
    if (result != ChunkCodex::DONE ||
        (content_length != UNBOUNDED && body_size != content_length)) {
      body_size.errata().error(R"(Invalid chunked response: expected {} bytes, drained {} bytes. Chunk is done: {}.)",
                   content_length, body_size.result(), result != ChunkCodex::DONE);
      return body_size;
    }
    body_size.errata().diag("Drained {} chunked bytes.", body_size.result());
  } else {
    body_size = initial.size();
    while (body_size < content_length) {
      ssize_t n = read({buff.data(), std::min(content_length - body_size,
                                              MAX_DRAIN_BUFFER_SIZE)});
      // Do not update body_size with n yet because read may return a negative
      // value on error conditions. If there is an error on read, then we close
      // the connection. Thus we check is_closed() here.
      if (is_closed()) {
        if (content_length == UNBOUNDED) {
          body_size.errata().diag("Connection closed on unbounded body");
        } else {
          body_size.errata().error(
              R"(Response underrun: received {} bytes  of content, expected {}, when file closed because {}.)",
              body_size.result(), content_length, swoc::bwf::Errno{});
        }
        break;
      }
      body_size.result() += n;
    }
    if (body_size > content_length) {
      body_size.errata().error(
          R"(Invalid response: expected {} fixed bytes, drained {} byts.)",
          content_length, body_size.result());
      return body_size;
    }
    body_size.errata().diag("Drained {} bytes.", body_size.result());
  }
  return body_size;
}

swoc::Rv<ssize_t> Stream::write_body(HttpHeader const &hdr) {
  swoc::Rv<ssize_t> bytes_written;
  std::error_code ec;

  bytes_written.errata().diag("Transmit {} byte body {}{}.", hdr._content_size,
       swoc::bwf::If(hdr._content_length_p, "[CL]"),
       swoc::bwf::If(hdr._chunked_p, "[chunked]"));

  if (hdr._content_size > 0 ||
      (hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
    TextView content;
    if (hdr._content_data) {
      content = TextView{hdr._content_data, hdr._content_size};
    } else {
      // If hdr._content_data is null, then there was no explicit description
      // of the body data via the data node. Instead we'll use our generated
      // HttpHeader::_content.
      content = TextView{HttpHeader::_content.data(), hdr._content_size};
    }

    if (hdr._chunked_p) {
      ChunkCodex codex;
      std::tie(bytes_written, ec) = codex.transmit(*this, content);
    } else {
      bytes_written = write(content);
      ec = std::error_code(errno, std::system_category());

      if (!hdr._content_length_p) { // no content-length, must close to signal
                                    // end of body
        bytes_written.errata().diag("No content length, status {}. Closing the connection.", hdr._status);
        close();
      }
    }

    if (bytes_written != hdr._content_size) {
      bytes_written.errata().error(R"(Body write{} failed with {} of {} bytes written: {}.)",
                   swoc::bwf::If(hdr._chunked_p, " [chunked]"), bytes_written.result(),
                   hdr._content_size, ec);
    }
  } else if (hdr._content_size == 0 && hdr._status &&
             !HttpHeader::STATUS_NO_CONTENT[hdr._status] && !hdr._chunked_p &&
             !hdr._content_length_p) {
    // There's no body but the status expects one, so signal no body with EOS.
    bytes_written.errata().diag("No CL or TE, status {}: closing.", hdr._status);
    close();
  }

  return bytes_written;
}

swoc::Rv<ssize_t> TLSStream::write(swoc::TextView view) {
  int total_size = view.size();
  swoc::Rv<ssize_t> num_written = 0;
  while (num_written < total_size) {
    errno = 0;
    int n = SSL_write(this->_ssl, view.data() + num_written,
                      view.size() - num_written);
    if (n <= 0) {
      num_written.errata().error(R"(write failed: {}, errno: {})",
              swoc::bwf::SSLError{}, swoc::bwf::Errno{});
      return n;
    } else {
      num_written.result() += n;
    }
  }
  return num_written;
}

swoc::Errata Stream::set_fd(int fd) {
  swoc::Errata errata;
  this->close();
  _fd = fd;
  return errata;
}

// Wait upon the client to initiate a TSL handshake and then complete the handshake.
swoc::Errata TLSStream::accept() {
  swoc::Errata errata;
  _ssl = SSL_new(server_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL server object fd={} server_ctx={} err={}.)",
        get_fd(), server_ctx, swoc::bwf::SSLError{});
  } else {
    SSL_set_fd(_ssl, get_fd());
    int retval = SSL_accept(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_accept {}, {}.)",
          swoc::bwf::SSLError{}, swoc::bwf::Errno{});
    }
  }
  return errata;
}

swoc::Errata Stream::connect() {
  swoc::Errata errata;
  return errata;
}

// Initiate the TLS handshake.
swoc::Errata TLSStream::connect() {
  swoc::Errata errata;
  _ssl = SSL_new(client_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL client object fd={} client_ctx={} err={}.)",
        get_fd(), client_ctx, swoc::bwf::SSLError{});
  } else {
    SSL_set_fd(_ssl, get_fd());
    if (!_client_sni.empty()) {
      SSL_set_tlsext_host_name(_ssl, _client_sni.data());
    }
    int retval = SSL_connect(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_connect {}, {}.)",
          swoc::bwf::SSLError{}, swoc::bwf::Errno{});
    }
  }
  return errata;
}

void Stream::close() {
  if (!this->is_closed()) {
    ::close(_fd);
    _fd = -1;
  }
}

void TLSStream::close() {
  if (!this->is_closed()) {
    if (_ssl != nullptr) {
      SSL_free(_ssl);
      _ssl = nullptr;
    }
    super_type::close();
  }
}

swoc::file::path TLSStream::certificate_file;
swoc::file::path TLSStream::privatekey_file;
SSL_CTX *TLSStream::server_ctx = nullptr;
SSL_CTX *TLSStream::client_ctx = nullptr;

swoc::Errata TLSStream::init() {
  swoc::Errata errata;
  SSL_load_error_strings();
  SSL_library_init();

  server_ctx = SSL_CTX_new(TLS_server_method());
  if (!TLSStream::certificate_file.empty()) {
    if (!SSL_CTX_use_certificate_file(server_ctx,
                                      TLSStream::certificate_file.c_str(),
                                      SSL_FILETYPE_PEM)) {
      errata.error(R"(Failed to load cert from "{}": {}.)",
                   TLSStream::certificate_file,
                   swoc::bwf::SSLError{});
    } else {
      if (!TLSStream::privatekey_file.empty()) {
        if (!SSL_CTX_use_PrivateKey_file(server_ctx,
                                         TLSStream::privatekey_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}": {}.)",
                       TLSStream::privatekey_file,
                       swoc::bwf::SSLError{});
        }
      } else {
        if (!SSL_CTX_use_PrivateKey_file(server_ctx,
                                         TLSStream::certificate_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}": {}.)",
                       TLSStream::certificate_file,
                       swoc::bwf::SSLError{});
        }
      }
    }
  }
  client_ctx = SSL_CTX_new(TLS_client_method());
  if (!client_ctx) {
    errata.error(R"(Failed to create client_ctx: {}.)",
                 swoc::bwf::SSLError{});
  }
  return errata;
}

ChunkCodex::Result ChunkCodex::parse(swoc::TextView data,
                                     ChunkCallback const &cb) {
  while (data) {
    switch (_state) {
    case State::INIT:
      _state = State::SIZE;
      break;
    case State::SIZE:
      while (data && isxdigit(*data)) {
        _size_text.write(*data++);
      }
      if (data) {
        _size = swoc::svtou(_size_text.view(), nullptr, 16);
        _size_text.clear();
        _state = State::CR;
        break;
      }
    case State::POST_BODY_CR:
      if (*data == '\r') {
        _state = State::POST_BODY_LF;
      }
      ++data;
      break;
    case State::CR:
      if (*data == '\r') {
        _state = State::LF;
      }
      ++data;
      break;
    case State::POST_BODY_LF:
      if (*data == '\n') {
        _state = State::SIZE;
        ++data;
        _off = 0;
      } else {
        _state = State::FINAL;
        return DONE;
      }
      break;
    case State::LF:
      if (*data == '\n') {
        if (_size) {
          _state = State::BODY;
          ++data;
          _off = 0;
        } else {
          _state = State::FINAL;
          return DONE;
        }
      }
      break;
    case State::BODY: {
      size_t n = std::min(data.size(), _size - _off);
      cb({data.data(), n}, _off, _size);
      data.remove_prefix(n);
      if ((_off += n) >= _size) {
        _state = State::POST_BODY_CR;
      }
    } break;
    case State::FINAL:
      return DONE;
    }
  }
  return CONTINUE;
}

std::tuple<ssize_t, std::error_code>
ChunkCodex::transmit(Stream &stream, swoc::TextView data, size_t chunk_size) {
  static const std::error_code NO_ERROR;
  static constexpr swoc::TextView ZERO_CHUNK{"0\r\n\r\n"};

  swoc::LocalBufferWriter<10> w; // 8 bytes of size (32 bits) CR LF
  ssize_t n;
  ssize_t total = 0;
  while (data) {
    if (data.size() < chunk_size) {
      chunk_size = data.size();
    }
    w.clear().print("{:x}{}", chunk_size, HTTP_EOL);
    n = stream.write(w.view());
    if (n > 0) {
      n = stream.write({data.data(), chunk_size});
      if (n > 0) {
        total += n;
        if (n == chunk_size) {
          w.clear().print("{}",
                          HTTP_EOL); // Each chunk much terminate with CRLF
          stream.write(w.view());
          data.remove_prefix(chunk_size);
        } else {
          return {total, std::error_code(errno, std::system_category())};
        }
      }
    } else {
      return {total, std::error_code(errno, std::system_category())};
    }
  }
  n = stream.write(ZERO_CHUNK);
  if (n != ZERO_CHUNK.size()) {
    return {total, std::error_code(errno, std::system_category())};
  }
  return {total, NO_ERROR};
};

void HttpHeader::global_init() {
  FIELD_CONTENT_LENGTH = localize("Content-Length"_tv);
  FIELD_TRANSFER_ENCODING = localize("Transfer-Encoding"_tv);

  STATUS_NO_CONTENT[100] = true;
  STATUS_NO_CONTENT[204] = true;
  STATUS_NO_CONTENT[304] = true;
  for (auto code = 400; code < 600; code++) {
    STATUS_NO_CONTENT[code] = true;
  }

  RuleCheck::options_init();
}

void RuleCheck::options_init() {
  options = RuleOptions();
  options[swoc::TextView(YAML_RULE_EQUALS)] = make_equality;
  options[swoc::TextView(YAML_RULE_PRESENCE)] = make_presence;
  options[swoc::TextView(YAML_RULE_ABSENCE)] = make_absence;
}

std::shared_ptr<RuleCheck> RuleCheck::find(const YAML::Node &node,
                                           swoc::TextView name) {
  swoc::Errata errata;
  auto flag_identifier = swoc::TextView(node[YAML_RULE_TYPE_KEY].Scalar());
  auto fn_iter = options.find(flag_identifier);
  if (fn_iter == options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", flag_identifier);
    return nullptr;
  }
  return fn_iter->second(
      name, HttpHeader::localize(node[YAML_RULE_DATA_KEY].Scalar()));
}

std::shared_ptr<RuleCheck> RuleCheck::make_equality(swoc::TextView name,
                                                    swoc::TextView value) {
  // Issue: Cannot use make_unique with polymorphism?
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, value));
}

std::shared_ptr<RuleCheck> RuleCheck::make_presence(swoc::TextView name,
                                                    swoc::TextView value) {
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name));
}

std::shared_ptr<RuleCheck> RuleCheck::make_absence(swoc::TextView name,
                                                   swoc::TextView value) {
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name));
}

EqualityCheck::EqualityCheck(swoc::TextView name, swoc::TextView value) {
  _name = name;
  _value = value;
}

PresenceCheck::PresenceCheck(swoc::TextView name) { _name = name; }

AbsenceCheck::AbsenceCheck(swoc::TextView name) { _name = name; }

bool EqualityCheck::test(swoc::TextView name, swoc::TextView value) const {
  swoc::Errata errata;
  if (name.empty())
    errata.info(R"(Equals Violation: Absent. Key: "{}", Correct Value: "{}")", _name,
         _value);
  else if (strcasecmp(value, _value))
    errata.info(
        R"(Equals Violation: Different. Key: "{}", Correct Value: "{}", Actual Value: "{}")",
        _name, _value, value);
  else {
    errata.info(R"(Equals Success: Key: "{}", Value: "{}")", _name, _value);
    return true;
  }
  return false;
}

bool PresenceCheck::test(swoc::TextView name, swoc::TextView value) const {
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}")", _name);
    return false;
  }
  errata.info(R"(Presence Success: Key: "{}", Value: "{}")", _name, value);
  return true;
}

bool AbsenceCheck::test(swoc::TextView name, swoc::TextView value) const {
  swoc::Errata errata;
  if (!name.empty()) {
    errata.info(R"(Absence Violation: Present. Key: "{}", Value: "{}")", _name, value);
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}")", _name);
  return true;
}

void HttpHeader::set_max_content_length(size_t n) {
  n = swoc::round_up<16>(n);
  _content.assign(static_cast<char *>(malloc(n)), n);
  for (size_t k = 0; k < n; k += 8) {
    swoc::FixedBufferWriter w{_content.data() + k, 8};
    w.print("{:07x} ", k / 8);
  };
}

swoc::Errata HttpHeader::update_content_length(swoc::TextView method) {
  swoc::Errata errata;
  size_t cl = std::numeric_limits<size_t>::max();
  _content_length_p = false;
  // Some methods ignore the Content-Length for the current transaction
  if (strcasecmp(method, "HEAD") == 0) {
    // Don't try chunked encoding later
    _content_size = 0;
    _content_length_p = true;
  } else if (auto spot{_fields_rules._fields.find(FIELD_CONTENT_LENGTH)};
             spot != _fields_rules._fields.end()) {
    cl = swoc::svtou(spot->second);
    if (_content_size != 0 && cl != _content_size) {
      errata.diag(R"(Conflicting sizes for "{}", using rule value {} instead of header value {}.)",
          FIELD_CONTENT_LENGTH, cl, _content_size);
    }
    _content_size = cl;
    _content_length_p = true;
  }
  return errata;
}

swoc::Errata HttpHeader::update_transfer_encoding() {
  _chunked_p = false;
  if (auto spot{_fields_rules._fields.find(FIELD_TRANSFER_ENCODING)};
      spot != _fields_rules._fields.end()) {
    if (0 == strcasecmp("chunked", spot->second)) {
      _chunked_p = true;
    }
  }
  return {};
}

swoc::Errata HttpHeader::serialize(swoc::BufferWriter &w) const {
  swoc::Errata errata;

  if (_status) {
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
  } else if (_method) {
    w.print("{} {} HTTP/{}{}", _method, _url, _http_version, HTTP_EOL);
  } else {
    errata.error(R"(Unable to write header: no status nor method.)");
  }

  for (auto const &[name, value] : _fields_rules._fields) {
    w.write(name).write(": ").write(value).write(HTTP_EOL);
  }
  w.write(HTTP_EOL);

  return errata;
}

swoc::Errata HttpFields::parse_fields_node(YAML::Node const &node) {
  swoc::Errata errata;

  if (auto rules_node{node[YAML_FIELDS_KEY]}; rules_node) {
    if (rules_node.IsSequence()) {
      if (rules_node.size() > 0) {
        auto result{this->parse_fields_rules(rules_node)};
        if (!result.is_ok()) {
          errata.error("Failed to parse fields and rules at {}", node.Mark());
          errata.note(result);
        }
      } else {
        errata.info(R"(Fields and rules node at {} is an empty list.)",
                    rules_node.Mark());
      }
    } else {
      errata.info(R"(Fields and rules node at {} is not a sequence.)",
                  rules_node.Mark());
    }
  } else {
    errata.info(R"(Node at {} is missing a fields node.)", node.Mark());
  }
  return errata;
}

swoc::Errata
HttpFields::parse_fields_rules(YAML::Node const &fields_rules_node) {
  swoc::Errata errata;

  for (auto const &node : fields_rules_node) {
    if (node.IsSequence()) {
      if (node.size() == 3) {
        TextView name{HttpHeader::localize(node[0].Scalar())};
        std::shared_ptr<RuleCheck> tester = RuleCheck::find(node, name);
        if (!tester) {
          errata.error("Field rule at {} does not have a valid flag ({})",
                       node.Mark(), node[2].Scalar());
        } else {
          _rules[name] = tester;
        }
      } else if (node.size() == 2) {
        TextView name{HttpHeader::localize(node[0].Scalar())};
        _fields[name] = node[1].Scalar();
      } else {
        errata.error("Field or rule node at {} is not a sequence of length 2 "
                     "or 3 as required.",
                     node.Mark());
      }
    } else {
      errata.error("Field or rule at {} is not a sequence as required.",
                   node.Mark());
    }
  }
  return errata;
}

swoc::Errata HttpHeader::load(YAML::Node const &node) {
  swoc::Errata errata;

  if (node[YAML_HTTP_VERSION_KEY]) {
    _http_version = this->localize(node[YAML_HTTP_VERSION_KEY].Scalar());
  } else {
    _http_version = "1.1";
  }

  if (node[YAML_HTTP_STATUS_KEY]) {
    auto status_node{node[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && 0 < n && n <= 599) {
        _status = n;
      } else {
        errata.error(
            R"("{}" value "{}" at {} must be an integer in the range [1..599].)",
            YAML_HTTP_STATUS_KEY, text, status_node.Mark());
      }
    } else {
      errata.error(
          R"("{}" value at {} must be an integer in the range [1..599].)",
          YAML_HTTP_STATUS_KEY, status_node.Mark());
    }
  }

  if (node[YAML_HTTP_REASON_KEY]) {
    auto reason_node{node[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      _reason = this->localize(reason_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must be a string.)",
                   YAML_HTTP_REASON_KEY, reason_node.Mark());
    }
  }

  if (node[YAML_HTTP_METHOD_KEY]) {
    auto method_node{node[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      _method = this->localize(method_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must be a string.)",
                   YAML_HTTP_REASON_KEY, method_node.Mark());
    }
  }

  if (node[YAML_HTTP_URL_KEY]) {
    auto url_node{node[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      _url = url_node.Scalar();
    } else {
      errata.error(R"("{}" value at {} must be a string.)", YAML_HTTP_URL_KEY,
                   url_node.Mark());
    }
  }

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      swoc::Errata result = _fields_rules.parse_fields_rules(field_list_node);
      if (result.is_ok()) {
        errata.note(this->update_content_length(_method));
        errata.note(this->update_transfer_encoding());
      } else {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(result);
      }
    }
  }

  // Do this after header so it can override transfer encoding.
  if (auto content_node{node[YAML_CONTENT_KEY]}; content_node) {
    if (content_node.IsMap()) {
      if (auto xf_node{content_node[YAML_CONTENT_TRANSFER_KEY]}; xf_node) {
        TextView xf{xf_node.Scalar()};
        if (0 == strcasecmp("chunked"_tv, xf)) {
          _chunked_p = true;
        } else if (0 == strcasecmp("plain"_tv, xf)) {
          _chunked_p = false;
        } else {
          errata.error(
              R"(Invalid value "{}" for "{}" key at {} in "{}" node at )", xf,
              YAML_CONTENT_TRANSFER_KEY, xf_node.Mark(), YAML_CONTENT_KEY,
              content_node.Mark());
        }
      }
      if (auto data_node{content_node[YAML_CONTENT_DATA_KEY]}; data_node) {
        Encoding enc{Encoding::TEXT};
        if (auto enc_node{content_node[YAML_CONTENT_ENCODING_KEY]}; enc_node) {
          TextView text{enc_node.Scalar()};
          if (0 == strcasecmp("uri"_tv, text)) {
            enc = Encoding::URI;
          } else if (0 == strcasecmp("plain"_tv, text)) {
            enc = Encoding::TEXT;
          } else {
            errata.error(R"(Unknown encoding "{}" at {}.)", text,
                         enc_node.Mark());
          }
        }
        TextView content{this->localize(data_node.Scalar(), enc)};
        _content_data = content.data();
        _content_size = content.size();
        if (content_node[YAML_CONTENT_LENGTH_KEY]) {
          errata.info(R"(The "{}" key is ignored if "{}" is present at {}.)",
                      YAML_CONTENT_LENGTH_KEY, YAML_CONTENT_DATA_KEY,
                      content_node.Mark());
        }
      } else if (auto size_node{content_node[YAML_CONTENT_LENGTH_KEY]};
                 size_node) {
        _content_size = swoc::svtou(size_node.Scalar());
      } else {
        errata.error(
            R"("{}" node at {} does not have a "{}" or "{}" key as required.)",
            YAML_CONTENT_KEY, node.Mark(), YAML_CONTENT_LENGTH_KEY,
            YAML_CONTENT_DATA_KEY);
      }
    } else {
      errata.error(R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY,
                   content_node.Mark());
    }
  }

  if (0 == _status && !_method) {
    errata.error(
        R"(HTTP header at {} has neither a status as a response nor a method as a request.)",
        node.Mark());
  }

  return errata;
}

std::string HttpHeader::make_key() {
  swoc::FixedBufferWriter w{nullptr};
  std::string key; // Should generally leave --key argument empty on cmd line.
  Binding binding(*this);
  w.print_n(binding, _key_format);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(binding, _key_format);
  return std::move(key);
}

bool HttpHeader::verify_headers(const HttpFields &rules_) const {
  // Remains false if no issue is observed
  // Setting true does not break loop because test() calls errata.diag()
  bool issue_exists = false;
  for (auto rule_iter = rules_._rules.cbegin();
       rule_iter != rules_._rules.cend(); ++rule_iter) {
    // Hashing uses strcasecmp internally
    auto found_iter = _fields_rules._fields.find(rule_iter->first);
    if (found_iter == _fields_rules._fields.cend()) {
      if (!rule_iter->second->test(swoc::TextView(), swoc::TextView())) {
        issue_exists = true;
      }
    } else {
      if (!rule_iter->second->test(found_iter->first,
                                   swoc::TextView(found_iter->second))) {
        issue_exists = true;
      }
    }
  }
  return issue_exists;
}

swoc::TextView HttpHeader::localize(char const *c_str) {
  return self_type::localize(TextView{c_str, strlen(c_str) + 1});
}

swoc::TextView HttpHeader::localize(TextView text) {
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  } else if (!_frozen) {
    auto span{_arena.alloc(text.size()).rebind<char>()};
    std::transform(text.begin(), text.end(), span.begin(), &tolower);
    TextView local{span.data(), text.size()};
    _names.insert(local);
    return local;
  }
  return text;
}

swoc::TextView HttpHeader::localize(TextView text, Encoding enc) {
  if (Encoding::URI == enc) {
    auto span{_arena.require(text.size()).remnant().rebind<char>()};
    auto spot = text.begin(), limit = text.end();
    char *dst = span.begin();
    while (spot < limit) {
      if (*spot == '%' && (spot + 1 < limit && isxdigit(spot[1]) &&
                           (spot + 2 < limit && isxdigit(spot[2])))) {
        *dst++ = swoc::svto_radix<16>(TextView{spot + 1, spot + 3});
        spot += 3;
      } else {
        *dst++ = *spot++;
      }
    }
    TextView text{span.data(), dst};
    _arena.alloc(text.size());
    return text;
  }
  return self_type::localize(text);
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_request(swoc::TextView data) {
  swoc::Rv<ParseResult> zret;

  if (swoc::TextView::npos == data.rfind(HTTP_EOH)) {
    zret = PARSE_INCOMPLETE;
  } else {
    data.remove_suffix(HTTP_EOH.size());

    auto first_line{data.take_prefix_at('\n')};
    if (first_line) {
      first_line.remove_suffix_if(&isspace);
      _method = this->localize(first_line.take_prefix_if(&isspace));
      _url = this->localize(
          first_line.ltrim_if(&isspace).take_prefix_if(&isspace));

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{this->localize(value.take_prefix_at(':'))};
        value.trim_if(&isspace);
        if (name) {
          _fields_rules._fields[name] = value;
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in request.");
    }
  }
  return zret;
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_response(swoc::TextView data) {
  swoc::Rv<ParseResult> zret{PARSE_OK};
  auto eoh = data.find(HTTP_EOH);

  if (swoc::TextView::npos == eoh) {
    zret = PARSE_INCOMPLETE;
  } else {
    data = data.prefix(eoh);

    auto first_line{data.take_prefix_at('\n').rtrim_if(&isspace)};
    if (first_line) {
      auto version{first_line.take_prefix_if(&isspace)};
      auto status{first_line.ltrim_if(&isspace).take_prefix_if(&isspace)};
      _status = swoc::svtou(status);

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        //        auto name{this->localize(value.take_prefix_at(':'))};
        auto name{value.take_prefix_at(':')};
        value.trim_if(&isspace);
        if (name) {
          _fields_rules._fields[name] = value;
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in response.");
    }
  }
  return zret;
}

swoc::BufferWriter &HttpHeader::Binding::
operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const {
  static constexpr TextView FIELD_PREFIX{"field."};
  TextView name{spec._name};
  if (name.starts_with_nocase(FIELD_PREFIX)) {
    name.remove_prefix(FIELD_PREFIX.size());
    if (auto spot{_hdr._fields_rules._fields.find(name)};
        spot != _hdr._fields_rules._fields.end()) {
      bwformat(w, spec, spot->second);
    } else {
      bwformat(w, spec, "*N/A*");
    }
  } else if (0 == strcasecmp("url"_tv, name)) {
    bwformat(w, spec, _hdr._url);
  } else {
    bwformat(w, spec, "*N/A*");
  }
  return w;
}

namespace swoc {
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       HttpHeader const &h) {
  w.write("Headers:\n"sv);
  for (auto const &[key, value] : h._fields_rules._fields) {
    w.print(R"(- "{}": "{}"{})", key, value, '\n');
  }
  return w;
}

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       bwf::SSLError const &error) {

  // Hand rolled, might not be totally compliant everywhere, but probably close
  // enough. The long string will be locally accurate. Clang requires the double
  // braces.
  static const std::array<std::string_view, 11> SHORT_NAME = {{
    "SSL_ERROR_NONE: ",
    "SSL_ERROR_SSL: ",
    "SSL_ERROR_WANT_READ: ",
    "SSL_ERROR_WANT_WRITE: ",
    "SSL_ERROR_WANT_X509_LOOKUP: ",
    "SSL_ERROR_SYSCALL: ",
    "SSL_ERROR_ZERO_RETURN: ",
    "SSL_ERROR_WANT_CONNECT: ",
    "SSL_ERROR_WANT_ACCEPT: ",
    "SSL_ERROR_WANT_ASYNC: ",
    "SSL_ERROR_WANT_ASYNC_JOB: ",
  }};

  auto short_name = [](int n) { return 0 <= n && n < int(SHORT_NAME.size()) ? SHORT_NAME[n] : "Unknown: "sv; };
  static const bwf::Format number_fmt{"[{}]"sv}; // numeric value format.
  if (spec.has_numeric_type()) {                 // if numeric type, print just the numeric part.
    w.print(number_fmt, error._e);
  } else {
    w.write(short_name(error._e));
    w.write(ERR_reason_error_string(error._e));
    if (spec._type != 's' && spec._type != 'S') {
      w.write(' ');
      w.print(number_fmt, error._e);
    }
  }
  return w;
}
} // namespace swoc

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler) {
  auto errata = handler.file_open(path);
  if (errata.is_ok()) {
    std::error_code ec;
    std::string content{swoc::file::load(path, ec)};
    if (ec.value()) {
      errata.error(R"(Error loading "{}": {})", path, ec);
    } else {
      YAML::Node root;
      HttpFields global_fields_rules;
      try {
        root = YAML::Load(content);
        yaml_merge(root);
      } catch (std::exception const &ex) {
        errata.warn(R"(Exception: {} in "{}".)", ex.what(), path);
      }
      if (errata.is_ok()) {
        if (root[YAML_META_KEY]) {
          auto meta_node{root[YAML_META_KEY]};
          if (meta_node[YAML_GLOBALS_KEY]) {
            auto globals_node{meta_node[YAML_GLOBALS_KEY]};
            // Path not passed to later calls than Load_Replay_File.
            errata.note(global_fields_rules.parse_fields_node(globals_node));
          }
        } else {
          errata.info(R"(No meta node ("{}") at "{}":{}.)", YAML_META_KEY,
                      path, root.Mark().line);
        }
        handler.config = VerificationConfig{&global_fields_rules};
        if (root[YAML_SSN_KEY]) {
          auto ssn_list_node{root[YAML_SSN_KEY]};
          if (ssn_list_node.IsSequence()) {
            if (ssn_list_node.size() > 0) {
              for (auto const &ssn_node : ssn_list_node) {
                // HeaderRules ssn_rules = global_rules;
                auto result{handler.ssn_open(ssn_node)};
                if (result.is_ok()) {
                  if (ssn_node[YAML_TXN_KEY]) {
                    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                    if (txn_list_node.IsSequence()) {
                      if (txn_list_node.size() > 0) {
                        for (auto const &txn_node : txn_list_node) {
                          // HeaderRules txn_rules = ssn_rules;
                          result = handler.txn_open(txn_node);
                          if (result.is_ok()) {
                            if (auto creq_node{txn_node[YAML_CLIENT_REQ_KEY]};
                                creq_node) {
                              result.note(handler.client_request(creq_node));
                            }
                            if (auto preq_node{txn_node[YAML_PROXY_REQ_KEY]};
                                preq_node) { // global_rules appears to be being
                                             // copied
                              result.note(handler.proxy_request(preq_node));
                            }
                            if (auto ursp_node{txn_node[YAML_SERVER_RSP_KEY]};
                                ursp_node) {
                              result.note(handler.server_response(ursp_node));
                            }
                            if (auto prsp_node{txn_node[YAML_PROXY_RSP_KEY]};
                                prsp_node) {
                              result.note(handler.proxy_response(prsp_node));
                            }
                            result.note(handler.txn_close());
                          }
                        }
                      } else {
                        result.info(
                            R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
                            txn_list_node.Mark(), ssn_node.Mark(), path);
                      }
                    } else {
                      result.error(
                          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
                          txn_list_node.Mark(), ssn_node.Mark(), path);
                    }
                  } else {
                    result.error(R"(Session at "{}":{} has no "{}" key.)",
                                 path, ssn_node.Mark().line, YAML_TXN_KEY);
                  }
                  result.note(handler.ssn_close());
                }
                errata.note(result);
              }
            } else {
              errata.diag(R"(Session list at "{}":{} is an empty list.)",
                          path, ssn_list_node.Mark().line);
            }
          } else {
            errata.error(R"("{}" value at "{}":{} is not a sequence.)",
                         YAML_SSN_KEY, path, ssn_list_node.Mark());
          }
        } else {
          errata.error(R"(No sessions list ("{}") at "{}":{}.)",
                       YAML_META_KEY, path, root.Mark().line);
        }
      }
    }
    handler.file_close();
  }
  return errata;
}

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads) {
  swoc::Errata errata;
  std::mutex local_mutex;
  std::error_code ec;

  dirent **elements = nullptr;

  auto stat{swoc::file::status(path, ec)};
  if (ec) {
    return Errata().error(R"(Invalid test directory "{}": [{}])", path, ec);
  } else if (swoc::file::is_regular_file(stat)) {
    return loader(path);
  } else if (!swoc::file::is_dir(stat)) {
    return Errata().error(R"("{}" is not a file or a directory.)", path);
  }

  if (0 == chdir(path.c_str())) {
    int n_sessions = scandir(
        ".", &elements,
        [](const dirent *entry) -> int {
          auto extension =
              swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at(
                  '.');
          return 0 == strcasecmp(extension, "json") ||
                 0 == strcasecmp(extension, "yaml");
        },
        &alphasort);
    if (n_sessions > 0) {
      std::atomic<int> idx{0};
      swoc::MemSpan<dirent *> entries{elements,
                                      static_cast<size_t>(n_sessions)};

      // Lambda suitable to spawn in a thread to load files.
      auto load_wrapper = [&]() -> void {
        int k;
        while ((k = idx++) < entries.count()) {
          auto result = (*loader)(swoc::file::path{entries[k]->d_name});
          std::lock_guard<std::mutex> lock(local_mutex);
          errata.note(result);
        }
      };

      errata.info("Loading {} replay files.", n_sessions);
      std::vector<std::thread> threads;
      threads.reserve(n_threads);
      for (int tidx = 0; tidx < n_threads; ++tidx) {
        threads.emplace_back(load_wrapper);
      }
      for (std::thread &thread : threads) {
        thread.join();
      }
    } else {
      errata.error(R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.error(R"(Failed to access directory "{}": {}.)", path,
                 swoc::bwf::Errno{});
  }
  return errata;
}

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target) {
  swoc::Errata errata;
  int offset = 0;
  int new_offset;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    swoc::IPEndpoint addr;
    if (!addr.parse(name)) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(addr);
  }
  return errata;
}

swoc::Errata resolve_ips(std::string arg,
                         std::deque<swoc::IPEndpoint> &target) {
  swoc::Errata errata;
  int offset = 0;
  int new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    auto &&[tmp_target, result] = Resolve_FQDN(name);
    if (!result.is_ok()) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(tmp_target);
  }
  return errata;
}

swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView fqdn) {
  swoc::Rv<swoc::IPEndpoint> zret;
  swoc::TextView host_str, port_str;
  in_port_t port;
  static constexpr in_port_t MAX_PORT{std::numeric_limits<in_port_t>::max()};

  if (swoc::IPEndpoint::tokenize(fqdn, &host_str, &port_str)) {
    swoc::IPAddr addr;
    if (port_str) {
      swoc::TextView text(port_str);
      auto n = swoc::svto_radix<10>(text);
      if (text.empty() && 0 < n && n <= MAX_PORT) {
        port = htons(n);
        if (addr.parse(host_str)) {
          zret.result().assign(addr, port);
        } else {
          addrinfo *addrs;
          addrinfo hints;
          char buff[host_str.size() + 1];
          memcpy(buff, host_str.data(), host_str.size());
          buff[host_str.size()] = '\0';
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = 0;
          auto result = getaddrinfo(buff, nullptr, &hints, &addrs);
          if (0 == result) {
            zret.result().assign(addrs->ai_addr);
            zret.result().port() = port;
            freeaddrinfo(addrs);
          } else {
            zret.errata().error(R"(Failed to resolve "{}": {}.)", host_str,
                                swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.errata().error(R"(Port value {} out of range [ 1 .. {} ].)",
                            port_str, MAX_PORT);
      }
    } else {
      zret.errata().error(
          R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.errata().error(R"(Malformed address "{}".)", fqdn);
  }
  return std::move(zret);
}

using namespace std::chrono_literals;

void ThreadPool::wait_for_work(ThreadInfo *thread_info) {
  // ready to roll, add to the pool.
  {
    std::unique_lock<std::mutex> lock(_threadPoolMutex);
    _threadPool.push_back(thread_info);
    _threadPoolCvar.notify_all();
  }

  // wait for a notification there's a stream to process.
  {
    std::unique_lock<std::mutex> lock(thread_info->_mutex);
    bool condition_awoke = false;
    while (!thread_info->data_ready() && !condition_awoke) {
      thread_info->_cvar.wait_for(lock, 100ms);
    }
  }
}

ThreadInfo *ThreadPool::get_worker() {
  ThreadInfo *thread_info = nullptr;
  {
    std::unique_lock<std::mutex> lock(this->_threadPoolMutex);
    while (_threadPool.size() == 0) {
      if (_allThreads.size() > max_threads) {
        // Just sleep until a thread comes back
        _threadPoolCvar.wait(lock);
      } else { // Make a new thread
        // Some ugly stuff so that the thread can put a pointer to it's @c
        // std::thread in it's info. Circular dependency - there's no object
        // until after the constructor is called but the constructor needs
        // to be called to get the object. Sigh.
        _allThreads.emplace_back();
        // really? I have to do this to get an iterator / pointer to the
        // element I just added?
        std::thread *t = &*(std::prev(_allThreads.end()));
        *t = this->make_thread(t);
        _threadPoolCvar.wait(lock); // expect the new thread to enter
                                    // itself in the pool and signal.
      }
    }
    thread_info = _threadPool.front();
    _threadPool.pop_front();
  }
  return thread_info;
}

void ThreadPool::join_threads() {
  for (auto &thread : _allThreads) {
    thread.join();
  }
}
