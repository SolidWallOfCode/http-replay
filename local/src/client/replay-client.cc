#include <dirent.h>

#include <chrono>
#include <list>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "core/ArgParser.h"
#include "core/HttpReplay.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"

namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              std::chrono::milliseconds ms) {
  return bwformat(w, spec, ms.count()).write("ms");
}
} // namespace swoc

using swoc::TextView;

struct Txn {
  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Response to expect.
};

struct Ssn {
  std::list<Txn> _txn;
  std::string _path;
  unsigned _line_no = 0;
};
std::mutex LoadMutex;

std::list<Ssn> Session_List;

bool Proxy_Mode = false;

class ClientReplayFileHandler : public ReplayFileHandler {
  swoc::Errata file_open(swoc::file::path const &path);
  swoc::Errata ssn_open(YAML::Node const &node) override;
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata client_request(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata proxy_response(YAML::Node const &node) override;
  swoc::Errata txn_close() override;
  swoc::Errata ssn_close() override;

  void txn_reset();
  void ssn_reset();

  std::string _path;
  Ssn _ssn;
  Txn _txn;
};

swoc::Errata ClientReplayFileHandler::file_open(swoc::file::path const &path) {
  _path = path.string();
  return {};
}

void ClientReplayFileHandler::ssn_reset() {
  _ssn.~Ssn();
  new (&_ssn) Ssn;
}

void ClientReplayFileHandler::txn_reset() {
  _txn.~Txn();
  new (&_txn) Txn;
}

swoc::Errata ClientReplayFileHandler::ssn_open(YAML::Node const &node) {
  _ssn._path = _path;
  _ssn._line_no = node.Mark().line;
  return {};
}

swoc::Errata ClientReplayFileHandler::txn_open(YAML::Node const &) {
  LoadMutex.lock();
  return {};
}

swoc::Errata ClientReplayFileHandler::client_request(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::proxy_request(YAML::Node const &node) {
  if (Proxy_Mode) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::proxy_response(YAML::Node const &node) {
  if (!Proxy_Mode) {
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::server_response(YAML::Node const &node) {
  if (Proxy_Mode) {
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata ClientReplayFileHandler::txn_close() {
  _ssn._txn.emplace_back(std::move(_txn));
  LoadMutex.unlock();
  return {};
}

swoc::Errata ClientReplayFileHandler::ssn_close() {
  {
    std::lock_guard<std::mutex> lock(LoadMutex);
    Session_List.emplace_back(std::move(_ssn));
  }
  this->ssn_reset();
  return {};
}

swoc::Errata Run_Transaction(int fd, Txn const &txn, bool &eos_p) {
  std::cout << "Transaction" << std::endl;
  swoc::Errata errata{txn._req.transmit(fd)};
  if (errata.is_ok()) {
    size_t eoh_offset = 0;
    HttpHeader rsp_hdr;
    swoc::LocalBufferWriter<MAX_RSP_HDR_SIZE> w;
    while (w.remaining() > 0) {
      auto n = read(fd, w.aux_data(), w.remaining());
      if (n > 0) {
        size_t start =
            std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
        w.commit(n);
        size_t offset = w.view().substr(start).find(HTTP_EOH);
        if (TextView::npos != offset) {
          eoh_offset = start + offset + HTTP_EOH.size();
          break;
        }
      } else if (EINTR != errno) {
        errata.error(
            R"(Connection closed unexpectedly while waiting for response header - {}.)",
            swoc::bwf::Errno{});
        eos_p = true;
        break;
      }
    }

    if (eoh_offset) {
      auto result{rsp_hdr.parse_response(w.view().substr(0, eoh_offset))};
      if (result.is_ok()) {
        size_t left_overs = w.size() - eoh_offset;
        // soak up content.
        std::string buff;
        size_t content_length = std::numeric_limits<size_t>::max();
        if (auto spot{rsp_hdr._fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
            spot != rsp_hdr._fields.end()) {
          content_length = swoc::svtou(spot->second);
          if (content_length < left_overs) {
            errata.error(
                R"(Response overrun - received {} bytes of content, expected {}.)",
                left_overs, content_length);
            return errata;
          }
          content_length -= left_overs;
        }
        buff.reserve(std::min<size_t>(content_length, MAX_DRAIN_BUFFER_SIZE));

        size_t body_size = 0;
        while (body_size < content_length) {
          size_t n =
              read(fd, buff.data(),
                   std::min(content_length - body_size, MAX_DRAIN_BUFFER_SIZE));
          if (n <= 0) {
            if (content_length != std::numeric_limits<size_t>::max()) {
              errata.error(
                  R"(Response underrun - recieved {} bytes of content, expected {}, when file closed because {}.)",
                  body_size, content_length, swoc::bwf::Errno{});
            }
            eos_p = true;
            break;
          }
          body_size += n;
        }
      } else {
        errata.error(R"(Invalid response.)");
        errata.note(result);
      }
    } else if (errata.is_ok()) {
      errata.error(R"(Response exceeded maximum size {}.)", MAX_RSP_HDR_SIZE);
    }
  }
  return errata;
}

swoc::Errata Run_Session(Ssn const &ssn, swoc::IPEndpoint const &target) {
  swoc::Errata errata;
  int socket_fd = -2;

  std::cout << "Session" << std::endl;

  for (auto const &txn : ssn._txn) {
    if (-1 == socket_fd) {
      errata.info(
          R"(Session ["{}":{}] closed before all transactions completed.)",
          ssn._path, ssn._line_no);
    }
    if (0 > socket_fd) {
      socket_fd = socket(target.family(), SOCK_STREAM, 0);
      if (socket_fd >= 0) {
        if (0 != connect(socket_fd, &target.sa, target.size())) {
          errata.error(R"(Failed to connect to {} - {}.)", target,
                       swoc::bwf::Errno{});
          break;
        }
      } else {
        errata.error(R"(Failed to open socket - {})", swoc::bwf::Errno{});
        break;
      }
    }
    bool eos_p = false;
    errata = Run_Transaction(socket_fd, txn, eos_p);
    if (eos_p) {
      close(socket_fd);
      socket_fd = -1;
    }
    if (!errata.is_ok()) {
      break;
    }
  }
  if (0 <= socket_fd) {
    close(socket_fd);
  }
  return std::move(errata);
}

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  static constexpr swoc::TextView COMMAND_RUN{"run"};
  static constexpr swoc::TextView COMMAND_RUN_ARGS{
      "Arguments:\n\t<dir>: Directory containing replay files.\n\t<upstream>: "
      "Upstream destination for requests."};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
  /// Error reporting.
  swoc::Errata erratum;
};

void Engine::command_run() {
  auto args{arguments.get("run")};
  dirent **elements = nullptr;

  if (args.size() < 2) {
    erratum.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN,
                  COMMAND_RUN_ARGS);
    status_code = 1;
    return;
  }

  if (arguments.get("--no-proxy")) {
    Proxy_Mode = true;
  }

  auto &&[target, target_result] = Resolve_FQDN(args[1]);
  if (!target_result.is_ok()) {
    std::cerr << target_result;
    return;
  }

  std::cout << "Loading " << args[0] << std::endl;
  auto result =
      Load_Replay_Directory(swoc::file::path{args[0]},
                            [](swoc::file::path const &file) -> swoc::Errata {
                              ClientReplayFileHandler handler;
                              return Load_Replay_File(file, handler);
                            },
                            10);
  if (!result.is_ok()) {
    std::cerr << result;
    return;
  }

  auto start = std::chrono::high_resolution_clock::now();
  unsigned n_ssn = 0;
  unsigned n_txn = 0;
  for (auto const &ssn : Session_List) {
    result = Run_Session(ssn, target);
    if (!result.is_ok()) {
      std::cerr << result;
      break;
    }
    if (result.count()) {
      std::cout << result;
    }
    ++n_ssn;
    n_txn += ssn._txn.size();
  }
  auto delta = std::chrono::high_resolution_clock::now() - start;
  std::cout << swoc::LocalBufferWriter<256>{}
                   .print("{} transactions in {} sessions in {}.", n_ssn, n_txn,
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              delta))
                   .view()
            << std::endl;
};

int main(int argc, const char *argv[]) {
  Engine engine;

  engine.parser.add_option("--debug", "", "Enable debugging output")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command(Engine::COMMAND_RUN.data(), Engine::COMMAND_RUN_ARGS.data(),
                   "", MORE_THAN_ONE_ARG_N,
                   [&]() -> void { engine.command_run(); })
      .add_option("--no-proxy", "", "Use proxy data instead of client data.");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  engine.arguments.invoke();

  if (!engine.erratum.is_ok()) {
    std::cerr << engine.erratum;
  }
  return engine.status_code;
}