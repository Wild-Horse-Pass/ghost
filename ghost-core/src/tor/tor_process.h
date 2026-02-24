// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TOR_TOR_PROCESS_H
#define BITCOIN_TOR_TOR_PROCESS_H

#include <util/fs.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <thread>

class ArgsManager;

/** Manages an embedded Tor subprocess.
 *
 * Spawns a Tor binary as a child process with a minimal generated torrc,
 * monitors it, and shuts it down cleanly when ghostd exits. If Tor dies
 * unexpectedly, ghostd is shut down (no clearnet fallback).
 */
class TorProcess
{
public:
    /** @param shutdown_fn  Called if Tor dies unexpectedly (triggers ghostd shutdown). */
    TorProcess(const fs::path& tor_binary, const fs::path& data_dir,
               uint16_t socks_port, uint16_t control_port,
               std::function<bool()> shutdown_fn);
    ~TorProcess();

    /** Start the Tor process and wait for bootstrap.
     *  Returns true if Tor bootstrapped within the timeout. */
    bool Start(std::chrono::seconds timeout);

    /** Signal the monitor thread to stop. */
    void Interrupt();

    /** Stop the Tor process (SIGTERM, then SIGKILL after 10s). */
    void Stop();

    /** Check if the Tor process is still running. */
    bool IsRunning() const;

    /** Get the PID of the Tor subprocess (-1 if not running). */
    pid_t GetPid() const { return m_pid; }

private:
    /** Write a minimal torrc to the data directory. */
    bool WriteTorrc();

    /** Wait for "Bootstrapped 100%" in Tor's log file. */
    bool WaitForBootstrap(std::chrono::seconds timeout);

    /** Monitor thread: watches for unexpected Tor exit. */
    void MonitorThread();

    fs::path m_tor_binary;
    fs::path m_data_dir;   // <datadir>/tor/
    fs::path m_torrc_path;
    fs::path m_log_path;
    uint16_t m_socks_port;
    uint16_t m_control_port;
    std::function<bool()> m_shutdown_fn;
    pid_t m_pid{-1};
    std::atomic<bool> m_interrupt{false};
    std::thread m_monitor_thread;
};

/** Find a Tor binary: checks -torbin arg, then next to ghostd, then system paths.
 *  Returns std::nullopt if no binary found. */
std::optional<fs::path> FindTorBinary(const ArgsManager& args);

#endif // BITCOIN_TOR_TOR_PROCESS_H
