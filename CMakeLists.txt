cmake_minimum_required(VERSION 3.24)
project(actpub VERSION 0.1.0 LANGUAGES CXX)

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

set(SPDLOG_USE_STD_FORMAT ON)
set(LIBMW_BUILD_URL ON)
set(LIBMW_BUILD_SQLITE ON)
set(LIBMW_BUILD_HTTP_SERVER ON)
set(LIBMW_BUILD_CRYPTO ON)
set(INJA_USE_EMBEDDED_JSON FALSE)
set(INJA_BUILD_TESTS FALSE)
FetchContent_MakeAvailable(libmw ryml spdlog cxxopts json inja macrodown)

# OpenSSL
find_package(OpenSSL REQUIRED)

# SQLite3
find_package(SQLite3 REQUIRED)

set(INCLUDES
  ${libmw_SOURCE_DIR}/includes
  ${json_SOURCE_DIR}/single_include
  ${inja_SOURCE_DIR}/include
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
)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

set(SOURCE_FILES src/main.cpp src/config.cpp src/database.cpp src/app.cpp src/json_ld.cpp src/signature_verifier.cpp src/job_queue.cpp src/http_utils.cpp)

# Main Executable
add_executable(actpub ${SOURCE_FILES})
set_property(TARGET actpub PROPERTY CXX_STANDARD 23)
set_property(TARGET actpub PROPERTY CXX_EXTENSIONS FALSE)
target_link_libraries(actpub PRIVATE ${LIBS})
target_compile_options(actpub PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(actpub PRIVATE ${INCLUDES})

# Tests
add_executable(unit_tests 
  src/database_test.cpp 
  src/job_queue_test.cpp
  src/signature_verifier_test.cpp
  src/signature_integration_test.cpp
  src/json_ld_test.cpp
  src/config_test.cpp
  src/app_test.cpp
  src/database.cpp 
  src/config.cpp
  src/job_queue.cpp
  src/signature_verifier.cpp
  src/json_ld.cpp
  src/app.cpp
  src/http_utils.cpp
)
set_property(TARGET unit_tests PROPERTY CXX_STANDARD 23)
target_link_libraries(unit_tests PRIVATE ${LIBS} GTest::gtest_main GTest::gmock)
target_include_directories(unit_tests PRIVATE ${INCLUDES})
