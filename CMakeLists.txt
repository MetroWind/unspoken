# cmake -DUNSPOKEN_BUILD_TESTS=ON -B build . && cmake --build build -j
cmake_minimum_required(VERSION 3.24)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

project(Unspoken LANGUAGES CXX)
option(UNSPOKEN_BUILD_TESTS "Build unit tests" OFF)

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
set(LIBMW_BUILD_HTTP_SERVER ON)  # also provides AuthOpenIDConnect (auth.cpp)
set(LIBMW_BUILD_CRYPTO ON)
set(INJA_USE_EMBEDDED_JSON FALSE)
set(INJA_BUILD_TESTS FALSE)
FetchContent_MakeAvailable(libmw ryml spdlog cxxopts json inja macrodown)

if(UNSPOKEN_BUILD_TESTS)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
  )
  FetchContent_MakeAvailable(googletest)
endif()

# Generate commit.hpp carrying the git commit hash.
find_package(Git QUIET)
if(GIT_FOUND)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
endif()
if(NOT GIT_COMMIT_HASH)
  set(GIT_COMMIT_HASH "unknown")
endif()
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/src/commit.hpp.in
  ${CMAKE_CURRENT_SOURCE_DIR}/src/commit.hpp
  @ONLY)

set(SOURCE_FILES
  src/config.cpp
  src/config.hpp
  src/structs.hpp
  src/data.cpp
  src/data.hpp
  src/auth.cpp
  src/auth.hpp
  src/emoji.cpp
  src/emoji.hpp
  src/render.cpp
  src/render.hpp
  src/attachments.cpp
  src/attachments.hpp
  src/federation.cpp
  src/federation.hpp
  src/service.cpp
  src/service.hpp
  src/app.cpp
  src/app.hpp
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

set(INCLUDES
  ${libmw_SOURCE_DIR}/includes
  ${json_SOURCE_DIR}/single_include
  ${inja_SOURCE_DIR}/single_include/inja
)

add_executable(unspoken ${SOURCE_FILES} src/main.cpp)
set_property(TARGET unspoken PROPERTY CXX_STANDARD 23)
set_property(TARGET unspoken PROPERTY CXX_EXTENSIONS FALSE)
set_property(TARGET unspoken PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
# -Wno-error on the deprecated-literal-operator warning that the
# transitive third-party cpp-httplib header trips under C++23; our own
# code is still held to -Werror.
target_compile_options(unspoken PRIVATE
  -Wall -Wextra -Wpedantic -Wno-error=deprecated-literal-operator)
target_include_directories(unspoken PRIVATE ${INCLUDES})
target_link_libraries(unspoken PRIVATE ${LIBS})

if(UNSPOKEN_BUILD_TESTS)
  set(TEST_FILES
    src/config_test.cpp
    src/data_test.cpp
    src/auth_test.cpp
    src/service_test.cpp
    src/federation_test.cpp
  )

  # ctest --test-dir build
  add_executable(unspoken_test ${SOURCE_FILES} ${TEST_FILES})
  set_property(TARGET unspoken_test PROPERTY CXX_STANDARD 23)
  set_property(TARGET unspoken_test PROPERTY CXX_EXTENSIONS FALSE)
  set_property(TARGET unspoken_test PROPERTY COMPILE_WARNING_AS_ERROR TRUE)
  target_compile_options(unspoken_test PRIVATE
    -Wall -Wextra -Wpedantic -Wno-error=deprecated-literal-operator
    # GCC's -O2 maybe-uninitialized analysis trips false positives on the
    # heavy std::optional access in test bodies; relax it for tests only.
    -Wno-error=maybe-uninitialized)
  target_include_directories(unspoken_test PRIVATE
    ${INCLUDES}
    ${googletest_SOURCE_DIR}/googletest/include
    ${googletest_SOURCE_DIR}/googlemock/include
  )
  target_link_libraries(unspoken_test PRIVATE
    ${LIBS}
    GTest::gtest_main
    GTest::gmock_main
  )

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(unspoken_test
    # Need this so that the unit tests can find templates/fixtures.
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
