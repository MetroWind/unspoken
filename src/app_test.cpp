#include <gtest/gtest.h>
#include "app.hpp"
#include "database.hpp"
#include "config.hpp"
#include <filesystem>

class AppTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_path = "test_app.db";
        if (std::filesystem::exists(db_path)) std::filesystem::remove(db_path);
        
        Config::get().db_path = db_path;
        Config::get().server_url_root = "http://localhost:8080";
    }

    void TearDown() override {
        if (std::filesystem::exists(db_path)) std::filesystem::remove(db_path);
    }

    std::string db_path;
};

TEST_F(AppTest, Instantiation) {
    auto db = std::make_unique<Database>(db_path);
    db->init();
    
    mw::HTTPServer::ListenAddress listen = mw::IPSocketInfo{"127.0.0.1", 0};
    App app(std::move(db), listen);
    // Setup is called in constructor via HTTPServer constructor calling setup()? 
    // No, HTTPServer::setup() is usually called by start() or manually.
    // In App::App, we initialize members.
}
