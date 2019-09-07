cmake_minimum_required(VERSION 3.12)

project(replay-server)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)
set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(replay-server
    replay-server.cc
)

target_link_libraries(replay-server PUBLIC replay-core ${CMAKE_INSTALL_LIBDIR}/libyaml-cpp.a Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

message("server bindir ${CMAKE_INSTALL_BINDIR}")
install(TARGETS replay-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS replay-server
    EXPORT replay-server-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-server-config
    NAMESPACE replay-server::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-server
    )
export(TARGETS replay-server FILE replay-server-config.cmake)
