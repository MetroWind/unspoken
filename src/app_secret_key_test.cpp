#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app.hpp"
#include "config.hpp"
#include "database_mock.hpp"

using ::testing::_;
using ::testing::Return;

class AppSecretKeyTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Config::get().secret_key = ""; // Reset
    }
};

TEST_F(AppSecretKeyTest, ConfigHasKey)
{
    Config::get().secret_key = "config_key";

    ::testing::NiceMock<DatabaseMock> db;
    EXPECT_CALL(db, getSystemConfig(_)).Times(0);

    App::initSecretKey(db);

    EXPECT_EQ(Config::get().secret_key, "config_key");
}

TEST_F(AppSecretKeyTest, ConfigEmpty_DbHasKey)
{
    ::testing::NiceMock<DatabaseMock> db;
    EXPECT_CALL(db, getSystemConfig("secret_key"))
        .WillOnce(Return(std::make_optional("db_key")));
    EXPECT_CALL(db, setSystemConfig(_, _)).Times(0);

    App::initSecretKey(db);

    EXPECT_EQ(Config::get().secret_key, "db_key");
}

TEST_F(AppSecretKeyTest, ConfigEmpty_DbEmpty)
{
    ::testing::NiceMock<DatabaseMock> db;
    EXPECT_CALL(db, getSystemConfig("secret_key"))
        .WillOnce(Return(std::nullopt));

    EXPECT_CALL(db, setSystemConfig("secret_key", _)).Times(1);

    App::initSecretKey(db);

    EXPECT_NE(Config::get().secret_key, "");
    EXPECT_EQ(Config::get().secret_key.length(), 32);
}
