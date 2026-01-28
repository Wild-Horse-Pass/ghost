// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GSP_GSP_H
#define BITCOIN_GSP_GSP_H

#include <memory>
#include <string>
#include <cstdint>
#include <atomic>
#include <filesystem>
#include <util/fs.h>

namespace node {
struct NodeContext;
} // namespace node

namespace gsp {

/**
 * Configuration for the GSP (Ghost Service Protocol) server.
 * GSP enables light wallets to interact with the Ghost network
 * without running a full node.
 */
struct GspConfig {
    //! Port to listen on for GSP HTTP/WebSocket connections
    uint16_t port{8900};

    //! Maximum number of concurrent WebSocket connections
    uint32_t max_connections{100};

    //! Data directory for GSP-specific data (wallet registry, etc.)
    fs::path data_dir;

    //! JWT secret for session tokens (auto-generated if empty)
    std::string jwt_secret;

    //! Enable rate limiting
    bool rate_limit_enabled{true};
};

/**
 * GSP Server - Ghost Service Protocol implementation.
 *
 * Provides HTTP REST endpoints and WebSocket connections for light wallets:
 * - Wallet registration and authentication (WalletProof + JWT)
 * - Balance and UTXO queries
 * - BIP-157/158 compact block filters for privacy-preserving Ghost Lock queries
 * - Real-time notifications via WebSocket subscriptions
 *
 * The server integrates directly with the node's chainman and mempool
 * for direct chain queries, eliminating the need for a separate proxy.
 */
class GspServer {
public:
    explicit GspServer(node::NodeContext& node, const GspConfig& config);
    ~GspServer();

    // Non-copyable, non-movable
    GspServer(const GspServer&) = delete;
    GspServer& operator=(const GspServer&) = delete;
    GspServer(GspServer&&) = delete;
    GspServer& operator=(GspServer&&) = delete;

    /**
     * Start the GSP server.
     * Registers HTTP handlers and starts the WebSocket listener.
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop the GSP server.
     * Gracefully closes all connections and unregisters handlers.
     */
    void Stop();

    /**
     * Interrupt the GSP server.
     * Called during shutdown to signal pending operations to stop.
     */
    void Interrupt();

    /**
     * Check if the server is running.
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get the current number of WebSocket connections.
     */
    uint32_t GetConnectionCount() const { return m_connection_count.load(); }

    /**
     * Get the number of registered wallets.
     */
    uint32_t GetRegisteredWalletCount() const;

    /**
     * Get server info for health/status endpoints.
     */
    struct ServerInfo {
        std::string protocol_version;
        std::string network;
        uint32_t connections;
        uint32_t registered_wallets;
        std::string sync_status;
        uint64_t uptime_secs;
    };
    ServerInfo GetServerInfo() const;

private:
    node::NodeContext& m_node;
    GspConfig m_config;
    std::atomic<bool> m_running{false};
    std::atomic<uint32_t> m_connection_count{0};
    int64_t m_start_time{0};

    // Forward declarations for implementation details
    class Impl;
    std::unique_ptr<Impl> m_impl;

    // HTTP handlers using HTTPRequest wrapper
    bool HandleHealthHTTP(class HTTPRequest* req);
    bool HandleInfoHTTP(class HTTPRequest* req);
    bool HandleRegisterHTTP(class HTTPRequest* req);
    bool HandleSessionHTTP(class HTTPRequest* req);
    bool HandleFilterHTTP(class HTTPRequest* req, int height);
    bool HandleFilterBatchHTTP(class HTTPRequest* req);
    bool HandleFilterHeadersHTTP(class HTTPRequest* req);
    bool HandleBlockHTTP(class HTTPRequest* req, const std::string& hash);

    // Legacy evhttp handlers (deprecated)
    bool HandleHealth(struct evhttp_request* req);
    bool HandleInfo(struct evhttp_request* req);
    bool HandleRegister(struct evhttp_request* req);
    bool HandleSession(struct evhttp_request* req);
    bool HandleFilter(struct evhttp_request* req, int height);
    bool HandleFilterHeaders(struct evhttp_request* req);
    bool HandleBlock(struct evhttp_request* req, const std::string& hash);
};

/**
 * GSP version string.
 */
inline constexpr const char* GSP_VERSION = "1.0.0";

/**
 * GSP protocol version number.
 */
inline constexpr uint32_t GSP_PROTOCOL_VERSION = 1;

/**
 * BIP-157 checkpoint interval (every 1000 blocks).
 */
inline constexpr int CFCHECKPT_INTERVAL = 1000;

} // namespace gsp

#endif // BITCOIN_GSP_GSP_H
