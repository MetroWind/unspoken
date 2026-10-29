#pragma once

#include <memory>
#include <string>
#include <mw/database.hpp>
#include <mw/error.hpp>

namespace ap
{

// A move-only write boundary on one borrowed SQLite connection.
// Destruction rolls back uncommitted work; the connection must outlive it.
class Transaction
{
public:
    // Begin an IMMEDIATE transaction, rejecting existing transactions.
    static mw::E<Transaction> begin(mw::SQLite& connection);
    // Borrow an existing host transaction without commit/rollback ownership.
    static mw::E<Transaction> join(mw::SQLite& connection);
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    // Transfer rollback responsibility to the new guard.
    Transaction(Transaction&& other) noexcept;
    Transaction& operator=(Transaction&&) = delete;
    ~Transaction();

    // Return the connection shared by host writes and library writes.
    mw::SQLite& connection() const
    {
        return *db;
    }
    // Whether this guard still owns an uncommitted transaction.
    bool active() const
    {
        return !finished;
    }
    // Commit all writes; a failure leaves rollback owned by this guard.
    mw::E<void> commit();
    // Explicitly roll back and report errors to the caller.
    mw::E<void> rollback();

private:
    explicit Transaction(mw::SQLite& connection) : db(&connection) {}
    mw::SQLite* db;
    bool finished = false;
    bool owns = true;
};

// A nested operation boundary that never commits its caller's transaction.
class Savepoint
{
public:
    // Begin a savepoint in an active caller-owned transaction.
    static mw::E<Savepoint> begin(Transaction& transaction);
    // Compose with an active transaction managed by the embedding host.
    static mw::E<Savepoint> begin(mw::SQLite& connection);
    Savepoint(const Savepoint&) = delete;
    Savepoint& operator=(const Savepoint&) = delete;
    // Transfer rollback responsibility to the new guard.
    Savepoint(Savepoint&& other) noexcept;
    Savepoint& operator=(Savepoint&&) = delete;
    ~Savepoint();
    // Keep this operation's changes within the outer transaction.
    mw::E<void> release();

private:
    Savepoint(mw::SQLite& connection, std::string savepoint_name)
        : db(&connection), name(std::move(savepoint_name))
    {
    }
    mw::SQLite* db;
    std::string name;
    bool finished = false;
};

// Check SQLite transaction state without exposing a raw connection publicly.
mw::E<bool> inTransaction(mw::SQLite& connection);

} // namespace ap
