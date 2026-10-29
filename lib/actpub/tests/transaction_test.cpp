#include <actpub/transaction.hpp>
#include <gtest/gtest.h>
#include <mw/test_utils.hpp>

TEST(Transaction, HostAndLibraryWritesCommitTogether)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE host(value TEXT)").has_value());
    ASSERT_TRUE(db->execute("CREATE TABLE ap_test(value TEXT)").has_value());
    {
        ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
        ASSERT_TRUE(tx.connection()
                        .execute("INSERT INTO host VALUES ('draft')")
                        .has_value());
        ASSERT_TRUE(tx.connection()
                        .execute("INSERT INTO ap_test VALUES ('queued')")
                        .has_value());
        ASSERT_TRUE(tx.commit().has_value());
    }
    EXPECT_EQ(db->evalToValue<int64_t>("SELECT count(*) FROM host").value(), 1);
    EXPECT_EQ(db->evalToValue<int64_t>("SELECT count(*) FROM ap_test").value(),
              1);
}

TEST(Transaction, ErrorRollsBackBothAndNestedBeginIsRejected)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE host(value TEXT)").has_value());
    {
        ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
        ASSERT_TRUE(
            db->execute("INSERT INTO host VALUES ('draft')").has_value());
        EXPECT_FALSE(ap::Transaction::begin(*db).has_value());
        EXPECT_TRUE(ap::inTransaction(*db).value());
    }
    EXPECT_EQ(db->evalToValue<int64_t>("SELECT count(*) FROM host").value(), 0);
    EXPECT_FALSE(ap::inTransaction(*db).value());
}

TEST(Transaction, SavepointRollbackDoesNotRollBackHostWrites)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE host(value TEXT)").has_value());
    ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
    ASSERT_TRUE(db->execute("INSERT INTO host VALUES ('keep')").has_value());
    {
        ASSIGN_OR_FAIL(auto operation, ap::Savepoint::begin(tx));
        ASSERT_TRUE(
            db->execute("INSERT INTO host VALUES ('drop')").has_value());
    }
    ASSERT_TRUE(tx.commit().has_value());
    EXPECT_EQ(db->evalToValue<std::string>("SELECT value FROM host").value(),
              "keep");
}

TEST(Transaction, SavepointReleaseDoesNotCommitOuterTransaction)
{
    ASSIGN_OR_FAIL(auto db, mw::SQLite::connectMemory());
    ASSERT_TRUE(db->execute("CREATE TABLE host(value TEXT)").has_value());
    {
        ASSIGN_OR_FAIL(auto tx, ap::Transaction::begin(*db));
        ASSIGN_OR_FAIL(auto operation, ap::Savepoint::begin(tx));
        ASSERT_TRUE(
            db->execute("INSERT INTO host VALUES ('drop')").has_value());
        ASSERT_TRUE(operation.release().has_value());
        EXPECT_TRUE(ap::inTransaction(*db).value());
    }
    EXPECT_EQ(db->evalToValue<int64_t>("SELECT count(*) FROM host").value(), 0);
}
