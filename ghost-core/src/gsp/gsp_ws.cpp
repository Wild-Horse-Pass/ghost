// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp_ws.h>
#include <gsp/gsp_auth.h>
#include <gsp/gsp_wallet.h>

#include <logging.h>
#include <node/context.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>
#include <index/blockfilterindex.h>

#include <map>
#include <mutex>
#include <thread>

namespace gsp {

std::string WsMessageTypeToString(WsMessageType type)
{
    switch (type) {
    case WsMessageType::Authenticate: return "Authenticate";
    case WsMessageType::GetBalance: return "GetBalance";
    case WsMessageType::GetUtxos: return "GetUtxos";
    case WsMessageType::GetGhostLocks: return "GetGhostLocks";
    case WsMessageType::GetTransactions: return "GetTransactions";
    case WsMessageType::GetBlockFilter: return "GetBlockFilter";
    case WsMessageType::GetBlock: return "GetBlock";
    case WsMessageType::SubscribeBalance: return "SubscribeBalance";
    case WsMessageType::SubscribePayments: return "SubscribePayments";
    case WsMessageType::SubscribeGhostLocks: return "SubscribeGhostLocks";
    case WsMessageType::Unsubscribe: return "Unsubscribe";
    case WsMessageType::Ping: return "Ping";
    case WsMessageType::AuthResult: return "AuthResult";
    case WsMessageType::BalanceResult: return "BalanceResult";
    case WsMessageType::UtxosResult: return "UtxosResult";
    case WsMessageType::GhostLocksResult: return "GhostLocksResult";
    case WsMessageType::TransactionsResult: return "TransactionsResult";
    case WsMessageType::BlockFilterResult: return "BlockFilterResult";
    case WsMessageType::BlockResult: return "BlockResult";
    case WsMessageType::SubscribeResult: return "SubscribeResult";
    case WsMessageType::UnsubscribeResult: return "UnsubscribeResult";
    case WsMessageType::Pong: return "Pong";
    case WsMessageType::BalanceUpdate: return "BalanceUpdate";
    case WsMessageType::PaymentReceived: return "PaymentReceived";
    case WsMessageType::GhostLockUpdate: return "GhostLockUpdate";
    case WsMessageType::NewBlock: return "NewBlock";
    case WsMessageType::Error: return "Error";
    }
    return "Unknown";
}

// WebSocket server implementation
class WsServer::Impl {
public:
    std::atomic<bool> running{false};
    std::mutex connections_mutex;
    std::map<uint64_t, WsConnection> connections;
    std::atomic<uint64_t> next_conn_id{1};
    std::thread accept_thread;

    // For mapping wallet_id to connection IDs
    std::mutex wallet_connections_mutex;
    std::multimap<std::string, uint64_t> wallet_connections;
};

WsServer::WsServer(node::NodeContext& node,
                   JwtManager& jwt,
                   WalletRegistry& registry,
                   uint16_t port,
                   uint32_t max_connections)
    : m_node(node)
    , m_jwt(jwt)
    , m_registry(registry)
    , m_port(port)
    , m_max_connections(max_connections)
    , m_impl(std::make_unique<Impl>())
{
}

WsServer::~WsServer()
{
    Stop();
}

bool WsServer::Start()
{
    if (m_impl->running.load()) {
        return true;
    }

    LogPrintf("GSP WS: Starting WebSocket server on port %d\n", m_port);

    // In a full implementation, this would:
    // 1. Create a WebSocket server using libevent
    // 2. Start accepting connections
    // 3. Handle WebSocket upgrade requests

    m_impl->running.store(true);
    LogPrintf("GSP WS: Server started\n");
    return true;
}

void WsServer::Stop()
{
    if (!m_impl->running.load()) {
        return;
    }

    LogPrintf("GSP WS: Stopping server...\n");
    m_impl->running.store(false);

    // Close all connections
    {
        std::lock_guard<std::mutex> lock(m_impl->connections_mutex);
        m_impl->connections.clear();
    }

    m_connection_count.store(0);
    LogPrintf("GSP WS: Server stopped\n");
}

void WsServer::Interrupt()
{
    m_impl->running.store(false);
}

void WsServer::Broadcast(WsMessageType sub_type, const std::string& message)
{
    std::lock_guard<std::mutex> lock(m_impl->connections_mutex);

    for (auto& [id, conn] : m_impl->connections) {
        if (conn.subscriptions.count(sub_type)) {
            // In a full implementation, send message via WebSocket
            LogPrintf("GSP WS: Broadcasting %s to connection %llu\n",
                      WsMessageTypeToString(sub_type), id);
        }
    }
}

void WsServer::SendToWallet(const std::string& wallet_id,
                            WsMessageType type,
                            const std::string& message)
{
    std::lock_guard<std::mutex> lock(m_impl->wallet_connections_mutex);

    auto range = m_impl->wallet_connections.equal_range(wallet_id);
    for (auto it = range.first; it != range.second; ++it) {
        // In a full implementation, send message via WebSocket
        LogPrintf("GSP WS: Sending %s to wallet %s (conn %llu)\n",
                  WsMessageTypeToString(type), wallet_id, it->second);
    }
}

void WsServer::NotifyNewBlock(const std::string& block_hash, int height)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("block_hash", block_hash);
    payload.pushKV("height", height);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::NewBlock);
    msg.pushKV("payload", payload);

    Broadcast(WsMessageType::SubscribeBalance, msg.write());
}

void WsServer::NotifyBalanceChange(const std::string& wallet_id,
                                   int64_t confirmed,
                                   int64_t unconfirmed)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("wallet_id", wallet_id);
    payload.pushKV("confirmed", confirmed);
    payload.pushKV("unconfirmed", unconfirmed);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::BalanceUpdate);
    msg.pushKV("payload", payload);

    SendToWallet(wallet_id, WsMessageType::BalanceUpdate, msg.write());
}

void WsServer::NotifyGhostLockChange(const std::string& wallet_id,
                                     const std::string& lock_id,
                                     const std::string& state)
{
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("wallet_id", wallet_id);
    payload.pushKV("lock_id", lock_id);
    payload.pushKV("state", state);

    UniValue msg(UniValue::VOBJ);
    msg.pushKV("type", (int)WsMessageType::GhostLockUpdate);
    msg.pushKV("payload", payload);

    SendToWallet(wallet_id, WsMessageType::GhostLockUpdate, msg.write());
}

// Message handlers

std::string WsServer::HandleAuthenticate(WsConnection& conn, const std::string& payload)
{
    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("token")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_token");
        return error.write();
    }

    std::string token = params["token"].get_str();
    auto wallet_id = m_jwt.VerifyToken(token);

    if (!wallet_id) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_token");
        return error.write();
    }

    // Check if wallet is active
    if (!m_registry.IsActive(*wallet_id)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "wallet_not_active");
        return error.write();
    }

    // Associate connection with wallet
    conn.wallet_id = *wallet_id;

    {
        std::lock_guard<std::mutex> lock(m_impl->wallet_connections_mutex);
        m_impl->wallet_connections.insert({*wallet_id, conn.id});
    }

    m_registry.UpdateLastSeen(*wallet_id);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::AuthResult);
    result.pushKV("success", true);
    result.pushKV("wallet_id", *wallet_id);

    return result.write();
}

std::string WsServer::HandleGetBalance(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // In a full implementation, query the UTXO set for the wallet's addresses
    // For now, return a placeholder

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BalanceResult);
    result.pushKV("confirmed", 0);
    result.pushKV("unconfirmed", 0);
    result.pushKV("locked", 0);

    return result.write();
}

std::string WsServer::HandleGetUtxos(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // In a full implementation, query UTXOs for the wallet's addresses
    UniValue utxos(UniValue::VARR);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::UtxosResult);
    result.pushKV("utxos", utxos);

    return result.write();
}

std::string WsServer::HandleGetGhostLocks(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // Ghost Locks are queried via BIP-157/158 filters on the client side
    // This endpoint is deprecated in favor of filter-based queries
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::GhostLocksResult);
    result.pushKV("message", "Use block filters for privacy-preserving Ghost Lock queries");

    return result.write();
}

std::string WsServer::HandleGetTransactions(WsConnection& conn, const std::string& payload)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    // Transactions should be retrieved via block filters for privacy
    UniValue txs(UniValue::VARR);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::TransactionsResult);
    result.pushKV("transactions", txs);

    return result.write();
}

std::string WsServer::HandleGetBlockFilter(WsConnection& conn, const std::string& payload)
{
    // This endpoint doesn't require authentication - filters are public

    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("height")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_height");
        return error.write();
    }

    int height = params["height"].getInt<int>();

    // Get the block filter from the index
    if (!m_node.chainman) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "node_not_ready");
        return error.write();
    }

    // In a full implementation, retrieve the BIP-157 filter for the block
    // This requires the blockfilterindex to be enabled

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BlockFilterResult);
    result.pushKV("height", height);
    result.pushKV("filter", ""); // BIP-157 filter data (hex encoded)
    result.pushKV("header", ""); // Filter header

    return result.write();
}

std::string WsServer::HandleGetBlock(WsConnection& conn, const std::string& payload)
{
    // This endpoint doesn't require authentication - blocks are public

    UniValue params;
    if (!params.read(payload)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "invalid_json");
        return error.write();
    }

    if (!params.exists("hash")) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "missing_hash");
        return error.write();
    }

    // In a full implementation, retrieve the block data
    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::BlockResult);
    result.pushKV("hash", params["hash"].get_str());
    result.pushKV("block", ""); // Block data (hex encoded)

    return result.write();
}

std::string WsServer::HandleSubscribe(WsConnection& conn, WsMessageType sub_type)
{
    if (conn.wallet_id.empty()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("type", (int)WsMessageType::Error);
        error.pushKV("error", "not_authenticated");
        return error.write();
    }

    conn.subscriptions.insert(sub_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::SubscribeResult);
    result.pushKV("success", true);
    result.pushKV("subscription", WsMessageTypeToString(sub_type));

    return result.write();
}

std::string WsServer::HandleUnsubscribe(WsConnection& conn, WsMessageType sub_type)
{
    conn.subscriptions.erase(sub_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("type", (int)WsMessageType::UnsubscribeResult);
    result.pushKV("success", true);
    result.pushKV("subscription", WsMessageTypeToString(sub_type));

    return result.write();
}

} // namespace gsp
