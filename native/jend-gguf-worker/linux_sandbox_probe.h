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
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>
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

// Deliberately requires a harmless inherited FD from our test parent:
 // refusing an absent FD avoids a false PASS from a naturally clean spawn.
inline bool parse_expected_fd(const char* encoded, int& fd) {
    if (!encoded || !encoded[0] || encoded[0] == '-' || encoded[0] == '+')
        return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(encoded, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < 3 || parsed > INT_MAX)
        return false;
    fd = static_cast<int>(parsed);
    return true;
}

// Close every fd >= 3 using the kernel in ONE fail-closed operation. No
// fallback to looping through getrlimit or /proc: such loops can miss FDs.
// This only sanitizes THIS TEST PROCESS, not production worker launch.
inline bool strip_inherited_launch_state(int canary_fd) {
    if (canary_fd < 3 || fcntl(canary_fd, F_GETFD) == -1) return false;
    if (std::getenv("JEND_TEST_INHERITED_ENV_CANARY") == nullptr) return false;
#ifndef __NR_close_range
    return false; // Unsupported kernel/syscall target; no silent downgrade.
#else
    if (syscall(__NR_close_range, 3u, ~0u, 0u) != 0) return false;
#endif
    errno = 0;
    if (fcntl(canary_fd, F_GETFD) != -1 || errno != EBADF) return false;
    if (::clearenv() != 0) return false;
    return std::getenv("JEND_TEST_INHERITED_ENV_CANARY") == nullptr;
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

    // Deny new file opens and common pathname mutation syscalls, even when
    // the invoking user could normally read its own E2EE secret files.
    // This is NOT an isolation of already-open/inherited file descriptors,
    // mmap, ioctl, /proc metadata or alternate access paths. Production
    // must independently close/broker all fds and use a complete OS sandbox.
#ifdef __NR_open
    deny(filter, __NR_open);
#endif
    deny(filter, __NR_openat);
#ifdef __NR_openat2
    deny(filter, __NR_openat2);
#endif
#ifdef __NR_creat
    deny(filter, __NR_creat);
#endif
#ifdef __NR_unlink
    deny(filter, __NR_unlink);
#endif
#ifdef __NR_unlinkat
    deny(filter, __NR_unlinkat);
#endif
#ifdef __NR_rename
    deny(filter, __NR_rename);
#endif
#ifdef __NR_renameat
    deny(filter, __NR_renameat);
#endif
#ifdef __NR_renameat2
    deny(filter, __NR_renameat2);
#endif
#ifdef __NR_linkat
    deny(filter, __NR_linkat);
#endif
#ifdef __NR_symlinkat
    deny(filter, __NR_symlinkat);
#endif
#ifdef __NR_mkdirat
    deny(filter, __NR_mkdirat);
#endif

    // Network sockets and new process creation are also denied. A full
    // allowlisted sandbox needs filesystem namespace, Landlock, separate
    // unprivileged identity and vetted OS handles.
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

inline bool verify_active_restrictions(const char* readable_canary_path, int closed_canary_fd) {
    // The specific harmless descriptor must remain closed after all later
    // library activity and kernel filter attachment.
    errno = 0;
    if (closed_canary_fd < 3 || fcntl(closed_canary_fd, F_GETFD) != -1
        || errno != EBADF) return false;
    if (std::getenv("JEND_TEST_INHERITED_ENV_CANARY") != nullptr) return false;
    if (!readable_canary_path || readable_canary_path[0] != '/') return false;
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
    if (errno != EPERM) return false;
    errno = 0;
    const int opened = openat(AT_FDCWD, readable_canary_path, O_RDONLY | O_CLOEXEC);
    if (opened >= 0) {
        close(opened);
        return false;
    }
    // A missing/unreadable canary could return ENOENT/EACCES. Requiring
    // exactly EPERM proves denial is due to the installed kernel filter.
    if (errno != EPERM) return false;

    errno = 0;
    const pid_t child = fork();
    if (child == 0) _exit(3);
    if (child > 0) {
        int child_status = 0;
        (void)waitpid(child, &child_status, 0);
        return false;
    }
    return errno == EPERM;
}
}  // namespace jend_linux_probe
