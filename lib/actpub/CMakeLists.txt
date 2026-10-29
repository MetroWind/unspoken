# Dependencies are supplied by the embedding project's libmw setup.
add_library(actpub
    src/transport.cpp
    src/transaction.cpp
    src/store.cpp
    src/engine.cpp
    src/identity.cpp
    src/collection.cpp
)
add_library(ActPub::actpub ALIAS actpub)
target_compile_features(actpub PUBLIC cxx_std_23)
set_target_properties(actpub PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(actpub PUBLIC
    include
    ${libmw_SOURCE_DIR}/includes
)
target_link_libraries(actpub PUBLIC
    mw::mw mw::url mw::crypto mw::sqlite nlohmann_json::nlohmann_json
    PRIVATE spdlog::spdlog)
target_compile_options(actpub PRIVATE -Wall -Wextra -Wpedantic -Werror)
