// M8.5.15.6b - Linux *protocol-only* restricted-process proof.
// This deliberately does NOT create a production native inference sandbox:
// it has NO filesystem namespace/ACL isolation, no brokered immutable GGUF
// descriptor, no authenticated executable and no E2EE secret isolation.
// Compile only for Linux x86_64/ARM64 when JEND_WITH_LLAMA is disabled.
#pragma once

#if !defined(__linux__) || defined(JEND_WITH_LLAMA)
#error "This probe is Linux-only and forbidden in inference-enabled builds"
#endif

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace jend_linux_probe {
#if defined(__x86_64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#else
#error "Unsupported Linux CPU ABI: never claim a sandbox on unknown architecture"
#endif

// Set both soft and hard limits. An unprivileged worker must not be able to
// simply raise its own soft resource limits later.
inline bool clamp(int resource, rlim_t maximum) {
    const rlimit limits = { maximum, maximum };
    return setrlimit(resource, &limits) == 0;
}

inline void deny(std::vector<sock_filter>& filter, std::uint32_t syscall_number) {
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_number, 0, 1));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
}

inline bool install_restrictions() {
    // Failure to apply ANY required limit is a hard refusal; no fallback.
    if (!clamp(RLIMIT_CORE, 0)
        || !clamp(RLIMIT_FSIZE, 0)
        || !clamp(RLIMIT_NOFILE, 64)
        || !clamp(RLIMIT_CPU, 2)
        || !clamp(RLIMIT_AS, 256 * 1024 * 1024)) return false;

    std::vector<sock_filter> filter;
    // Hard refusal if the kernel reports a different CPU ABI.
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 1, 0));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)));
#if defined(__x86_64__)
    // An x32-tagged syscall is outside this verified syscall-number policy.
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif

    // Network access from the worker is denied, but this does not prohibit
    // every possible IPC/file read. Strong isolation requires namespaces,
    // Linux Landlock, separate UID and vetted descriptor allowlists.
    deny(filter, __NR_socket);
    deny(filter, __NR_socketpair);
    deny(filter, __NR_connect);
    deny(filter, __NR_bind);
    deny(filter, __NR_listen);
    deny(filter, __NR_accept);
#ifdef __NR_accept4
    deny(filter, __NR_accept4);
#endif
    deny(filter, __NR_sendto);
    deny(filter, __NR_recvfrom);
    deny(filter, __NR_sendmsg);
    deny(filter, __NR_recvmsg);
    // Deny new subprocesses and self-re-execution after the filter is on.
    deny(filter, __NR_clone);
#ifdef __NR_clone3
    deny(filter, __NR_clone3);
#endif
#ifdef __NR_fork
    deny(filter, __NR_fork);
#endif
#ifdef __NR_vfork
    deny(filter, __NR_vfork);
#endif
    deny(filter, __NR_execve);
#ifdef __NR_execveat
    deny(filter, __NR_execveat);
#endif
#ifdef __NR_ptrace
    deny(filter, __NR_ptrace);
#endif
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    if (filter.size() > 65535) return false;
    const sock_fprog prog = {static_cast<unsigned short>(filter.size()), filter.data()};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) return false;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) return false;
    return true;
}

inline bool verify_active_restrictions() {
    if (prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1
        || prctl(PR_GET_SECCOMP, 0L, 0L, 0L, 0L) != SECCOMP_MODE_FILTER) {
        return false;
    }
    rlimit limits = {};
    if (getrlimit(RLIMIT_NOFILE, &limits) != 0 || limits.rlim_max != 64) return false;
    if (getrlimit(RLIMIT_AS, &limits) != 0
        || limits.rlim_max != 256 * 1024 * 1024) return false;
    if (getrlimit(RLIMIT_CORE, &limits) != 0 || limits.rlim_max != 0) return false;
    errno = 0;
    const int network = socket(AF_INET, SOCK_STREAM, 0);
    // An allowed socket MUST fail this probe. Never print PASS on a host
    // where the seccomp policy wasn't actually installed by the kernel.
    if (network != -1) {
        close(network);
        return false;
    }
    return errno == EPERM;
}
}  // namespace jend_linux_probe
