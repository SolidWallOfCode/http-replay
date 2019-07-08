cmake_minimum_required(VERSION 3.12)

project(replay-core)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

#set(OPENSSL_ROOT_DIR /opt/oath/openssl/1.1.1)
find_package(swoc++ CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(replay-core STATIC
    ArgParser.cc
    HttpReplay.cc
)

target_include_directories(replay-core PUBLIC)
target_link_libraries(replay-core PUBLIC swoc++::swoc++)

install(TARGETS replay-core ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS replay-core
    EXPORT replay-core-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT replay-core-config
    NAMESPACE replay-core::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/replay-core
    )
export(TARGETS replay-core FILE replay-core-config.cmake)
