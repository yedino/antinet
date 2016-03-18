cmake_minimum_required(VERSION 3.0)
project(crypto_test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -Ofast -pipe -lboost_system -lsodium")
file(GLOB EXTERNAL external/*cpp external/*hpp)
set(SOURCE_FILES main.cpp)

find_package(Boost COMPONENTS system REQUIRED)
find_library(LIBSODIUM sodium)

add_executable(crypto_test ${SOURCE_FILES} ${EXTERNAL})
target_link_libraries(crypto_test ${Boost_LIBRARIES})
target_link_libraries(crypto_test ${LIBSODIUM})
