cmake_minimum_required(VERSION 3.12)

project(replay-client)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(replay-client
    replay-client.cc
)

target_link_libraries(replay-client PUBLIC replay-core ${CMAKE_INSTALL_LIBDIR}/libyaml-cpp.a Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

install(TARGETS replay-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
message("client bindir ${CMAKE_INSTALL_BINDIR}")
install(TARGETS replay-client
    EXPORT replay-client-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-client-config
    NAMESPACE replay-clientl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-client
    )
export(TARGETS replay-client FILE replay-client-config.cmake)
