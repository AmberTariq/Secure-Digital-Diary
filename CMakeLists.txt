cmake_minimum_required(VERSION 3.10)
project(SecureDigitalDiary)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(secure_diary main.cpp)

target_include_directories(secure_diary PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(secure_diary PRIVATE ${SODIUM_LIBRARIES})
