// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <tor/tor_process.h>

#include <common/args.h>
#include <logging.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

TorProcess::TorProcess(const fs::path& tor_binary, const fs::path& data_dir,
                       uint16_t socks_port, uint16_t control_port,
                       std::function<bool()> shutdown_fn)
    : m_tor_binary(tor_binary),
      m_data_dir(data_dir),
      m_torrc_path(data_dir / "torrc"),
      m_log_path(data_dir / "tor.log"),
      m_socks_port(socks_port),
      m_control_port(control_port),
      m_shutdown_fn(std::move(shutdown_fn))
{
}

TorProcess::~TorProcess()
{
    Stop();
}

bool TorProcess::WriteTorrc()
{
    std::ofstream torrc(m_torrc_path);
    if (!torrc.is_open()) {
        LogPrintf("Tor mode: failed to write torrc at %s\n", fs::PathToString(m_torrc_path));
        return false;
    }

    torrc << "SocksPort 127.0.0.1:" << m_socks_port << "\n";
    torrc << "ControlPort 127.0.0.1:" << m_control_port << "\n";
    torrc << "CookieAuthentication 1\n";
    torrc << "DataDirectory " << fs::PathToString(m_data_dir) << "\n";
    torrc << "Log notice file " << fs::PathToString(m_log_path) << "\n";

    torrc.close();
    return true;
}

bool TorProcess::WaitForBootstrap(std::chrono::seconds timeout)
{
    const auto start = std::chrono::steady_clock::now();
    const std::string target = "Bootstrapped 100%";

    while (!m_interrupt.load(std::memory_order_relaxed)) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed >= timeout) {
            LogPrintf("Tor mode: bootstrap timed out after %llds\n",
                      std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
            return false;
        }

        // Check if Tor process is still alive
        if (!IsRunning()) {
            LogPrintf("Tor mode: process exited before bootstrapping\n");
            return false;
        }

        // Check log file for bootstrap completion
        std::ifstream log(m_log_path);
        if (log.is_open()) {
            std::string line;
            while (std::getline(log, line)) {
                if (line.find(target) != std::string::npos) {
                    LogPrintf("Tor mode: bootstrap complete\n");
                    return true;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return false;
}

bool TorProcess::Start(std::chrono::seconds timeout)
{
    // Create data directory
    try {
        fs::create_directories(m_data_dir);
    } catch (const std::filesystem::filesystem_error& e) {
        LogPrintf("Tor mode: failed to create data directory %s: %s\n",
                  fs::PathToString(m_data_dir), e.what());
        return false;
    }

    // Remove stale log so WaitForBootstrap doesn't match old output
    std::error_code ec;
    std::filesystem::remove(m_log_path, ec);

    if (!WriteTorrc()) {
        return false;
    }

    LogPrintf("Tor mode: starting Tor subprocess from %s\n", fs::PathToString(m_tor_binary));

    pid_t pid = fork();
    if (pid < 0) {
        LogPrintf("Tor mode: fork() failed: %s\n", strerror(errno));
        return false;
    }

    if (pid == 0) {
        // Child process: exec tor
        // Close inherited file descriptors (stdin/stdout/stderr → /dev/null)
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }

        std::string binary_str = fs::PathToString(m_tor_binary);
        std::string torrc_str = fs::PathToString(m_torrc_path);

        execl(binary_str.c_str(), binary_str.c_str(),
              "-f", torrc_str.c_str(),
              nullptr);

        // If execl returns, it failed
        _exit(127);
    }

    // Parent process
    m_pid = pid;
    LogPrintf("Tor mode: spawned Tor with PID %d\n", m_pid);

    if (!WaitForBootstrap(timeout)) {
        LogPrintf("Tor mode: bootstrap failed, stopping Tor\n");
        Stop();
        return false;
    }

    // Start monitor thread
    m_interrupt.store(false, std::memory_order_relaxed);
    m_monitor_thread = std::thread(&TorProcess::MonitorThread, this);

    return true;
}

void TorProcess::Interrupt()
{
    m_interrupt.store(true, std::memory_order_relaxed);
}

void TorProcess::Stop()
{
    Interrupt();

    if (m_monitor_thread.joinable()) {
        m_monitor_thread.join();
    }

    if (m_pid <= 0) return;

    // SIGTERM first
    LogPrintf("Tor mode: sending SIGTERM to PID %d\n", m_pid);
    kill(m_pid, SIGTERM);

    // Wait up to 10 seconds for clean exit
    for (int i = 0; i < 100 && IsRunning(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // SIGKILL if still alive
    if (IsRunning()) {
        LogPrintf("Tor mode: sending SIGKILL to PID %d\n", m_pid);
        kill(m_pid, SIGKILL);
    }

    // Reap zombie
    int status;
    waitpid(m_pid, &status, 0);
    LogPrintf("Tor mode: Tor process %d exited with status %d\n", m_pid, status);
    m_pid = -1;
}

bool TorProcess::IsRunning() const
{
    if (m_pid <= 0) return false;
    // Check /proc/<pid>/stat to detect zombies — kill(pid, 0) returns 0 for zombies
    std::string proc_path = "/proc/" + std::to_string(m_pid) + "/stat";
    std::ifstream stat_file(proc_path);
    if (!stat_file.is_open()) return false;  // Process doesn't exist
    std::string stat_line;
    std::getline(stat_file, stat_line);
    // Format: <pid> (<comm>) <state> ... — state 'Z' means zombie
    auto paren_close = stat_line.rfind(')');
    if (paren_close != std::string::npos && paren_close + 2 < stat_line.size()) {
        char state = stat_line[paren_close + 2];
        return state != 'Z' && state != 'X';
    }
    return kill(m_pid, 0) == 0;
}

void TorProcess::MonitorThread()
{
    LogPrintf("Tor mode: monitor thread started\n");

    while (!m_interrupt.load(std::memory_order_relaxed)) {
        // Check if Tor is still running
        int status;
        pid_t result = waitpid(m_pid, &status, WNOHANG);

        if (result > 0) {
            // Tor process exited
            LogPrintf("Tor mode: Tor process %d died unexpectedly (status %d). "
                      "Initiating shutdown to prevent clearnet exposure.\n",
                      m_pid, status);
            m_pid = -1;
            // Trigger ghostd shutdown — no clearnet fallback
            if (m_shutdown_fn) m_shutdown_fn();
            return;
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    LogPrintf("Tor mode: monitor thread exiting\n");
}

std::optional<fs::path> FindTorBinary(const ArgsManager& args)
{
    // 1. Check -torbin argument
    if (args.IsArgSet("-torbin")) {
        fs::path bin = fs::PathFromString(args.GetArg("-torbin", ""));
        if (fs::exists(bin)) {
            LogPrintf("Tor mode: using -torbin path: %s\n", fs::PathToString(bin));
            return bin;
        }
        LogPrintf("Tor mode: -torbin path not found: %s\n", fs::PathToString(bin));
        return std::nullopt;
    }

    // 2. Check next to ghostd binary (/proc/self/exe parent directory)
    {
        std::error_code ec;
        fs::path self{std::filesystem::read_symlink("/proc/self/exe", ec)};
        if (!ec) {
            fs::path sibling = self.parent_path() / "tor";
            if (fs::exists(sibling)) {
                LogPrintf("Tor mode: found Tor binary next to ghostd: %s\n", fs::PathToString(sibling));
                return sibling;
            }
        }
    }

    // 3. Check system paths
    const std::vector<fs::path> system_paths = {
        fs::PathFromString("/usr/bin/tor"),
        fs::PathFromString("/usr/local/bin/tor"),
        fs::PathFromString("/usr/sbin/tor"),
    };

    for (const auto& path : system_paths) {
        if (fs::exists(path)) {
            LogPrintf("Tor mode: found system Tor binary: %s\n", fs::PathToString(path));
            return path;
        }
    }

    return std::nullopt;
}
