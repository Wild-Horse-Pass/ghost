// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GSP_GSP_WS_H
#define BITCOIN_GSP_GSP_WS_H

#include <string>
#include <memory>
#include <functional>
#include <cstdint>
#include <vector>
#include <set>
#include <atomic>

namespace node {
struct NodeContext;
} // namespace node

namespace gsp {

class JwtManager;
class WalletRegistry;

/**
 * WebSocket message types for GSP protocol.
 */
enum class WsMessageType : uint8_t {
    // Client -> Server
    Authenticate = 1,
    GetBalance = 2,
    GetUtxos = 3,
    GetGhostLocks = 4,
    GetTransactions = 5,
    GetBlockFilter = 6,
    GetBlock = 7,
    SubscribeBalance = 10,
    SubscribePayments = 11,
    SubscribeGhostLocks = 12,
    Unsubscribe = 20,
    Ping = 30,

    // Server -> Client
    AuthResult = 101,
    BalanceResult = 102,
    UtxosResult = 103,
    GhostLocksResult = 104,
    TransactionsResult = 105,
    BlockFilterResult = 106,
    BlockResult = 107,
    SubscribeResult = 110,
    UnsubscribeResult = 120,
    Pong = 130,

    // Server -> Client (push notifications)
    BalanceUpdate = 201,
    PaymentReceived = 202,
    GhostLockUpdate = 203,
    NewBlock = 204,

    // Errors
    Error = 255
};

/**
 * WebSocket connection state.
 */
struct WsConnection {
    //! Unique connection ID
    uint64_t id;

    //! Authenticated wallet ID (empty if not authenticated)
    std::string wallet_id;

    //! Active subscriptions
    std::set<WsMessageType> subscriptions;

    //! Connection timestamp
    int64_t connected_at;

    //! Last activity timestamp
    int64_t last_activity;

    //! Remote address (for logging/rate limiting)
    std::string remote_addr;
};

/**
 * WebSocket message handler callback.
 */
using WsMessageHandler = std::function<std::string(
    WsConnection& conn,
    WsMessageType type,
    const std::string& payload
)>;

/**
 * GSP WebSocket Server - Handles real-time communication with light wallets.
 *
 * Protocol:
 * 1. Client connects to /gsp/ws/v1
 * 2. Client sends Authenticate message with JWT token
 * 3. Server validates JWT and associates connection with wallet_id
 * 4. Client can then send queries (GetBalance, etc.) and subscriptions
 * 5. Server pushes updates for subscribed events
 *
 * Message format: JSON
 * {
 *   "type": <message_type_number>,
 *   "id": <optional_request_id>,
 *   "payload": { ... }
 * }
 */
class WsServer {
public:
    WsServer(node::NodeContext& node,
             JwtManager& jwt,
             WalletRegistry& registry,
             uint16_t port,
             uint32_t max_connections);
    ~WsServer();

    // Non-copyable
    WsServer(const WsServer&) = delete;
    WsServer& operator=(const WsServer&) = delete;

    /**
     * Start the WebSocket server.
     */
    bool Start();

    /**
     * Stop the WebSocket server.
     */
    void Stop();

    /**
     * Interrupt pending operations.
     */
    void Interrupt();

    /**
     * Get current connection count.
     */
    uint32_t GetConnectionCount() const { return m_connection_count.load(); }

    /**
     * Broadcast a message to all connections subscribed to a specific type.
     */
    void Broadcast(WsMessageType sub_type, const std::string& message);

    /**
     * Send a message to a specific wallet.
     */
    void SendToWallet(const std::string& wallet_id,
                      WsMessageType type,
                      const std::string& message);

    /**
     * Notify about a new block (triggers NewBlock push to subscribers).
     */
    void NotifyNewBlock(const std::string& block_hash, int height);

    /**
     * Notify about a balance change for a wallet.
     */
    void NotifyBalanceChange(const std::string& wallet_id,
                             int64_t confirmed,
                             int64_t unconfirmed);

    /**
     * Notify about a Ghost Lock state change.
     */
    void NotifyGhostLockChange(const std::string& wallet_id,
                               const std::string& lock_id,
                               const std::string& state);

    // Message handlers (public for dispatch function access)
    std::string HandleAuthenticate(WsConnection& conn, const std::string& payload);
    std::string HandleGetBalance(WsConnection& conn, const std::string& payload);
    std::string HandleGetUtxos(WsConnection& conn, const std::string& payload);
    std::string HandleGetGhostLocks(WsConnection& conn, const std::string& payload);
    std::string HandleGetTransactions(WsConnection& conn, const std::string& payload);
    std::string HandleGetBlockFilter(WsConnection& conn, const std::string& payload);
    std::string HandleGetBlock(WsConnection& conn, const std::string& payload);
    std::string HandleSubscribe(WsConnection& conn, WsMessageType sub_type);
    std::string HandleUnsubscribe(WsConnection& conn, WsMessageType sub_type);

private:
    node::NodeContext& m_node;
    JwtManager& m_jwt;
    WalletRegistry& m_registry;
    uint16_t m_port;
    uint32_t m_max_connections;
    std::atomic<uint32_t> m_connection_count{0};

    class Impl;
    std::unique_ptr<Impl> m_impl;

    friend std::string DispatchMessage(WsServer& server, WsConnection& conn, const std::string& message);
    friend uint64_t CreateConnection(WsServer::Impl& impl, const std::string& remote_addr);
    friend void RemoveConnection(WsServer::Impl& impl, uint64_t conn_id);
    friend WsConnection* GetConnection(WsServer::Impl& impl, uint64_t conn_id);
};

/**
 * Convert WebSocket message type to string (for logging).
 */
std::string WsMessageTypeToString(WsMessageType type);

/**
 * Dispatch an incoming WebSocket message to the appropriate handler.
 * @param server The WebSocket server instance
 * @param conn The connection that sent the message
 * @param message The raw JSON message string
 * @return JSON response string
 */
std::string DispatchMessage(WsServer& server, WsConnection& conn, const std::string& message);

/**
 * Connection management helpers.
 */
uint64_t CreateConnection(WsServer::Impl& impl, const std::string& remote_addr);
void RemoveConnection(WsServer::Impl& impl, uint64_t conn_id);
WsConnection* GetConnection(WsServer::Impl& impl, uint64_t conn_id);

} // namespace gsp

#endif // BITCOIN_GSP_GSP_WS_H
