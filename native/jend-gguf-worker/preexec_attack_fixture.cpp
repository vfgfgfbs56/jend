// Linux-only adversarial, model-free fixture. Installs NO protections itself.
// The constructor must observe restrictions BEFORE main or C++ worker logic.
// Uses synthetic test canaries only. Never build into a production runtime.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef JEND_PRIVATE_CANARY_PATH
#error "compile with the synthetic private canary path"
#endif

extern char** environ;
namespace {
constexpr uintptr_t kParentMapping = UINT64_C(0x100000000);
constexpr rlim_t kRam = 128 * 1024 * 1024;
bool constructor_checked = false;

void need(bool condition) { if (!condition) _exit(97); }
void denied(long result) { need(result == -1 && errno == EPERM); }

#ifdef JEND_WITH_SEALED_MODEL_PROBE
void inspect_sealed_model_before_main() {
    constexpr char expected[] = "GGUF\x03\x00\x00\x00"
        "\x01\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "JEND-SYNTHETIC-PUBLIC-GGUF";
    struct stat statbuf{};
    need(fstat(4, &statbuf) == 0 && S_ISREG(statbuf.st_mode)
        && statbuf.st_size == sizeof(expected) - 1 && (statbuf.st_mode & 0111) == 0);
    need((fcntl(4, F_GETFL) & O_ACCMODE) == O_RDONLY);
    constexpr int seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL | 0x20;
    const int actual_seals = fcntl(4, F_GET_SEALS);
    need(actual_seals >= 0 && (actual_seals & seals) == seals);
    char bytes[sizeof(expected)] = {};
    need(syscall(SYS_pread64, 4, bytes, sizeof(bytes), 0) == sizeof(expected) - 1);
    need(std::memcmp(bytes, expected, sizeof(expected) - 1) == 0);
    errno = 0;
    need(write(4, "tamper", 6) == -1 && errno == EBADF);
    denied(syscall(SYS_ftruncate, 4, 0));
    denied(syscall(SYS_fchmod, 4, 0500));
    errno = 0;
    need(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, 4, 0) == MAP_FAILED
        && errno == EACCES);
    void* readonly = mmap(nullptr, 4096, PROT_READ, MAP_SHARED, 4, 0);
    need(readonly != MAP_FAILED && std::memcmp(readonly, expected, sizeof(expected) - 1) == 0);
    denied(mprotect(readonly, 4096, PROT_READ | PROT_EXEC));
    errno = 0;
    need(mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, 4, 0) == MAP_FAILED
        && errno == EPERM);
    need(munmap(readonly, 4096) == 0);
    char* const args[] = {const_cast<char*>("model"), nullptr};
    char* const env[] = {nullptr};
    denied(syscall(SYS_execveat, 4, "", args, env, AT_EMPTY_PATH));
    denied(syscall(SYS_pread64, UINT64_C(0x100000004), bytes, 1, 0));
}
#endif

__attribute__((constructor)) void attack_before_main() {
    need(environ && !environ[0]); // entire env empty, including loader variables
    need(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    need(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
    need(syscall(SYS_personality, UINT64_C(0xffffffff)) == 0);
    denied(syscall(SYS_personality, UINT64_C(0x00400000))); // READ_IMPLIES_EXEC
    for (int fd = 3; fd < 2048; ++fd) {
#ifdef JEND_WITH_SEALED_MODEL_PROBE
        if (fd == 4) { need(fcntl(fd, F_GETFD) >= 0); continue; }
#endif
        errno = 0;
        need(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    }
    unsigned char resident = 0;
    errno = 0;
    need(mincore(reinterpret_cast<void*>(kParentMapping), 4096, &resident) == -1
        && errno == ENOMEM); // exec replaced the secret-bearing parent mapping
    denied(syscall(SYS_openat, AT_FDCWD, JEND_PRIVATE_CANARY_PATH, O_RDONLY, 0));
    denied(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0));
    denied(syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0));
    denied(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0));
#ifdef SYS_clone3
    denied(syscall(SYS_clone3, nullptr, 0));
#endif
    denied(syscall(SYS_ptrace, PTRACE_ATTACH, getppid(), 0, 0));
    char byte = 0;
    iovec local{&byte, 1};
    iovec remote{reinterpret_cast<void*>(kParentMapping), 1};
    denied(syscall(SYS_process_vm_readv, getppid(), &local, 1, &remote, 1, 0));
    denied(syscall(SYS_kill, getppid(), 0)); // harmless existence probe
    denied(syscall(SYS_memfd_create, "escape", 0));
    denied(syscall(SYS_dup, 0));
    denied(syscall(SYS_ioctl, 0, 0, 0));
    denied(syscall(SYS_io_uring_setup, 1, nullptr));
    char* const args[] = {const_cast<char*>("true"), nullptr};
    char* const env[] = {nullptr};
    denied(syscall(SYS_execve, "/bin/true", args, env));
    // Regression for the absolute-path execveat bypass: the kernel ignores
    // dirfd for absolute paths. Seccomp's FD check alone is insufficient.
    errno = 0;
    need(syscall(SYS_execveat, 3, "/bin/true", args, env, AT_EMPTY_PATH) == -1
        && errno == EACCES); // mandatory Landlock EXECUTE denial
    errno = 0;
    need(syscall(SYS_execveat, 3, "", args, env, AT_EMPTY_PATH) == -1
        && errno == EBADF); // launch FD closed; no way to allocate another
    denied(syscall(SYS_execveat, UINT64_C(0x100000003), "/bin/true", args, env, AT_EMPTY_PATH));
    denied(syscall(SYS_prctl, UINT64_C(0x100000000) | PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    denied(syscall(SYS_prctl, PR_SET_SECCOMP, 0, 0, 0, 0));
    rlimit raised{kRam * 2, kRam * 2};
    denied(syscall(SYS_prlimit64, 0, RLIMIT_AS, &raised, nullptr));
    for (int resource : {RLIMIT_AS, RLIMIT_CPU, RLIMIT_NOFILE, RLIMIT_CORE}) {
        rlimit bound{};
        need(getrlimit(resource, &bound) == 0);
        constexpr rlim_t fds =
#ifdef JEND_WITH_SEALED_MODEL_PROBE
            5;
#else
            4;
#endif
        const rlim_t expected = resource == RLIMIT_AS ? kRam
            : resource == RLIMIT_CPU ? 1 : resource == RLIMIT_NOFILE ? fds : 0;
        need(bound.rlim_cur == expected && bound.rlim_max == expected);
    }
    errno = 0;
    need(mmap(nullptr, kRam * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == ENOMEM);
#if defined(__x86_64__)
    denied(syscall(SYS_socket | 0x40000000, AF_INET, SOCK_STREAM, 0)); // x32
#endif
#ifdef JEND_WITH_SEALED_MODEL_PROBE
    inspect_sealed_model_before_main();
#endif
    constructor_checked = true;
}
}

int main(int argc, char** argv) {
    need(constructor_checked && argc == 2);
#ifdef JEND_WITH_SEALED_MODEL_PROBE
    if (std::strcmp(argv[1], "--model-handle-probe") == 0) {
        constexpr char proof[] = "JEND-SEALED-GGUF-DATA-V1\n";
        return write(1, proof, sizeof(proof) - 1) == sizeof(proof) - 1 ? 0 : 98;
    }
#endif
    if (std::strcmp(argv[1], "--constructor-probe") == 0) {
        constexpr char proof[] = "JEND-PREEXEC-CONSTRUCTOR-V1\n";
        return write(1, proof, sizeof(proof) - 1) == sizeof(proof) - 1 ? 0 : 98;
    }
    if (std::strcmp(argv[1], "--stall") == 0) {
        for (;;) sleep(1); // deliberately never consumes stdin
    }
    if (std::strcmp(argv[1], "--cpu") == 0) {
        for (;;) asm volatile("" ::: "memory");
    }
    if (std::strcmp(argv[1], "--flood") == 0) {
        const char buffer[4096] = {};
        for (;;) if (write(1, buffer, sizeof(buffer)) <= 0) return 98;
    }
    return 99;
}
