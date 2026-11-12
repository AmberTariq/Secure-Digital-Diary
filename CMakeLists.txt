cmake_minimum_required(VERSION 3.10)
project(SecureDigitalDiary CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# v1: original Caesar-cipher version (no extra libraries)
add_executable(secure_diary_v1 v1-caesar-cipher/secure_diary_v1.cpp)

# v2: libsodium version
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
add_executable(secure_diary v2-libsodium/secure_diary.cpp)
target_link_libraries(secure_diary PRIVATE PkgConfig::SODIUM)
