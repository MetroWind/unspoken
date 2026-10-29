#include <actpub/transaction.hpp>

#include <atomic>
#include <format>
#include <utility>
#include <spdlog/spdlog.h>

namespace ap
{

mw::E<bool> inTransaction(mw::SQLite& connection)
{
    ASSIGN_OR_RETURN(auto statement, connection.statementFromStr("SELECT 1"));
    return sqlite3_get_autocommit(sqlite3_db_handle(statement.data())) == 0;
}

mw::E<Transaction> Transaction::begin(mw::SQLite& connection)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(connection));
    if(active)
        return std::unexpected(mw::runtimeError(
            "Cannot begin a write transaction inside another transaction"));
    DO_OR_RETURN(connection.execute("BEGIN IMMEDIATE"));
    return Transaction(connection);
}

mw::E<Transaction> Transaction::join(mw::SQLite& connection)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(connection));
    if(!active)
        return std::unexpected(mw::runtimeError("No host transaction to join"));
    Transaction transaction(connection);
    transaction.owns = false;
    return transaction;
}

Transaction::Transaction(Transaction&& other) noexcept
    : db(other.db), finished(std::exchange(other.finished, true)),
      owns(other.owns)
{
}

Transaction::~Transaction()
{
    if(!finished && owns)
    {
        auto result = rollback();
        if(!result)
            spdlog::error("ActivityPub transaction rollback failed: {}",
                          mw::errorMsg(result.error()));
    }
}

mw::E<void> Transaction::commit()
{
    if(!owns)
        return std::unexpected(mw::runtimeError("Host owns the transaction"));
    if(finished)
        return std::unexpected(mw::runtimeError("Transaction is finished"));
    DO_OR_RETURN(db->execute("COMMIT"));
    finished = true;
    return {};
}

mw::E<void> Transaction::rollback()
{
    if(!owns)
        return std::unexpected(mw::runtimeError("Host owns the transaction"));
    if(finished)
        return {};
    ASSIGN_OR_RETURN(bool active, inTransaction(*db));
    if(active)
        DO_OR_RETURN(db->execute("ROLLBACK"));
    finished = true;
    return {};
}

mw::E<Savepoint> Savepoint::begin(Transaction& transaction)
{
    if(!transaction.active())
        return std::unexpected(mw::runtimeError("Transaction is finished"));
    return begin(transaction.connection());
}

mw::E<Savepoint> Savepoint::begin(mw::SQLite& connection)
{
    ASSIGN_OR_RETURN(bool active, inTransaction(connection));
    if(!active)
        return std::unexpected(
            mw::runtimeError("Savepoint needs a transaction"));
    static std::atomic<uint64_t> NEXT_ID = 0;
    std::string name = std::format("ap_operation_{}", NEXT_ID.fetch_add(1));
    DO_OR_RETURN(connection.execute("SAVEPOINT " + name));
    return Savepoint(connection, std::move(name));
}

Savepoint::Savepoint(Savepoint&& other) noexcept
    : db(other.db), name(std::move(other.name)),
      finished(std::exchange(other.finished, true))
{
}

Savepoint::~Savepoint()
{
    if(!finished)
    {
        // An outer rollback may have removed this savepoint already.
        auto active = inTransaction(*db);
        if(active && *active)
        {
            auto rolled_back = db->execute("ROLLBACK TO " + name);
            auto released = db->execute("RELEASE " + name);
            if(!rolled_back || !released)
                spdlog::error("ActivityPub savepoint rollback failed");
        }
    }
}

mw::E<void> Savepoint::release()
{
    if(finished)
        return std::unexpected(mw::runtimeError("Savepoint is finished"));
    DO_OR_RETURN(db->execute("RELEASE " + name));
    finished = true;
    return {};
}

} // namespace ap
