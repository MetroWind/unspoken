cmake_minimum_required(VERSION 3.24)
project(unspoken VERSION 0.1.0 LANGUAGES CXX C)
option(UNSPOKEN_BUILD_TESTS "Build unit tests" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
FetchContent_Declare(
  libmw
  GIT_REPOSITORY https://github.com/MetroWind/libmw.git
)

FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.1.1
)

FetchContent_Declare(
  ryml
  GIT_REPOSITORY https://github.com/biojppm/rapidyaml.git
  GIT_TAG
  GIT_SHALLOW FALSE  # ensure submodules are checked out
)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.12.0
)

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

FetchContent_Declare(
  inja
  GIT_REPOSITORY https://github.com/pantor/inja.git
  GIT_TAG main
)

FetchContent_Declare(
    macrodown
    GIT_REPOSITORY https://git.xeno.darksair.org/macrodown.git
    GIT_TAG master
)

FetchContent_Declare(
  gumbo
  GIT_REPOSITORY https://github.com/google/gumbo-parser.git
  GIT_TAG master
)

set(SPDLOG_USE_STD_FORMAT ON)
set(LIBMW_BUILD_URL ON)
set(LIBMW_BUILD_SQLITE ON)
set(LIBMW_BUILD_HTTP_SERVER ON)
set(LIBMW_BUILD_CRYPTO ON)
set(INJA_USE_EMBEDDED_JSON FALSE)
set(INJA_BUILD_TESTS FALSE)
FetchContent_MakeAvailable(libmw ryml spdlog cxxopts json inja macrodown)

FetchContent_GetProperties(gumbo)
if(NOT gumbo_POPULATED)
  FetchContent_Populate(gumbo)
  add_library(gumbo STATIC
    ${gumbo_SOURCE_DIR}/src/attribute.c
    ${gumbo_SOURCE_DIR}/src/char_ref.c
    ${gumbo_SOURCE_DIR}/src/error.c
    ${gumbo_SOURCE_DIR}/src/parser.c
    ${gumbo_SOURCE_DIR}/src/string_buffer.c
    ${gumbo_SOURCE_DIR}/src/string_piece.c
    ${gumbo_SOURCE_DIR}/src/tag.c
    ${gumbo_SOURCE_DIR}/src/tokenizer.c
    ${gumbo_SOURCE_DIR}/src/utf8.c
    ${gumbo_SOURCE_DIR}/src/util.c
    ${gumbo_SOURCE_DIR}/src/vector.c
  )
  target_include_directories(gumbo PUBLIC ${gumbo_SOURCE_DIR}/src)
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)

# SQLite3
find_package(SQLite3 REQUIRED)

set(INCLUDES
  ${libmw_SOURCE_DIR}/includes
  ${json_SOURCE_DIR}/single_include
  ${inja_SOURCE_DIR}/include
  ${gumbo_SOURCE_DIR}/src
)
set(LIBS
  cxxopts
  mw::mw
  mw::url
  mw::sqlite
  mw::http-server
  mw::crypto
  ryml::ryml
  spdlog::spdlog
  MacroDown::MacroDown
  gumbo
)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

set(SOURCE_FILES src/main.cpp src/config.cpp src/database.cpp src/app.cpp src/json_ld.cpp src/signature_verifier.cpp src/job_queue.cpp src/http_utils.cpp src/html_sanitizer.cpp)

# Main Executable
add_executable(unspoken ${SOURCE_FILES})
set_property(TARGET unspoken PROPERTY CXX_STANDARD 23)
set_property(TARGET unspoken PROPERTY CXX_EXTENSIONS FALSE)
target_link_libraries(unspoken PRIVATE ${LIBS})
target_compile_options(unspoken PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(unspoken PRIVATE ${INCLUDES})

# Tests
if(SHRT_BUILD_TESTS)
  add_executable(unit_tests
    src/database_test.cpp
    src/job_queue_test.cpp
    src/signature_verifier_test.cpp
    src/signature_integration_test.cpp
    src/json_ld_test.cpp
    src/config_test.cpp
    src/app_test.cpp
    src/app_remote_user_test.cpp
    src/app_secret_key_test.cpp
    src/html_sanitizer_test.cpp
    src/database.cpp
    src/config.cpp
    src/job_queue.cpp
    src/signature_verifier.cpp
    src/json_ld.cpp
    src/app.cpp
    src/http_utils.cpp
    src/html_sanitizer.cpp
  )
  set_property(TARGET unit_tests PROPERTY CXX_STANDARD 23)
  target_link_libraries(unit_tests PRIVATE ${LIBS} GTest::gtest_main GTest::gmock)
  target_include_directories(unit_tests PRIVATE ${INCLUDES})
endif()
