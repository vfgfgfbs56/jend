// JEND M8.5.15 -- native GGUF CPU worker experiment.
//
// SAFETY: This is NOT a production sandbox or WeightVM consumer. The
// executable's infer-dev path MUST NOT be called by the product until an
// independently signed GGUF variant, immutable read-only admission, OS
// sandbox, and pinned upstream binary attestation have been implemented.
// The protocol-only build is used by CI and cannot open/load ANY model.
//
// Protocol v1 (stdout, no JSON or plaintext prompt logging):
// "JENDGGUF1" (9 bytes), followed by frames: type [1 byte], length [u32 BE],
// payload [max 16 KiB]. T = generated token bytes; D = done; N = no engine.
// stdin for --protocol-smoke / --infer-dev: [u32 BE][prompt <= 4096 bytes].
// Every process is one prompt. Cancellation is terminating the child process.
// Stdout is *only* protocol bytes. No secrets in argv or stderr.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#ifdef JEND_WITH_LLAMA
#include "llama.h"
#endif
#if defined(__linux__) && !defined(JEND_WITH_LLAMA)
#include "linux_sandbox_probe.h"
#endif

namespace {
constexpr uint32_t kMaxPromptBytes = 4096;
constexpr uint32_t kMaxFrameBytes = 16384;
#ifdef JEND_WITH_LLAMA
constexpr uint32_t kMaxModelContextTokens = 512;
constexpr int kMaxGeneratedTokens = 16;
constexpr uintmax_t kMaxDevModelBytes = UINT64_C(4) * 1024 * 1024 * 1024;
#endif

bool output_bytes(const char* bytes, size_t len) {
    std::cout.write(bytes, static_cast<std::streamsize>(len));
    return static_cast<bool>(std::cout);
}

void write_u32(uint32_t value) {
    char b[4] = {
        static_cast<char>((value >> 24) & 0xff),
        static_cast<char>((value >> 16) & 0xff),
        static_cast<char>((value >> 8) & 0xff),
        static_cast<char>(value & 0xff),
    };
    (void) output_bytes(b, sizeof(b));
}

bool send_frame(char type, const std::string& value) {
    if (value.size() > kMaxFrameBytes) return false;
    std::cout.put(type);
    write_u32(static_cast<uint32_t>(value.size()));
    return output_bytes(value.data(), value.size()) && static_cast<bool>(std::cout.flush());
}

bool read_prompt(std::string& prompt) {
    char b[4] = {};
    if (!std::cin.read(b, sizeof(b))) return false;
    const auto n = (static_cast<uint32_t>(static_cast<uint8_t>(b[0])) << 24) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 8) |
                    static_cast<uint32_t>(static_cast<uint8_t>(b[3]));
    if (n == 0 || n > kMaxPromptBytes) return false;
    prompt.resize(n);
    if (!std::cin.read(prompt.data(), static_cast<std::streamsize>(n))) return false;
    // This is a one-shot worker: no ambiguous trailing command or second
    // prompt is permitted. The parent MUST close its stdin after the frame.
    return std::cin.peek() == std::char_traits<char>::eof();
}

#ifdef JEND_WITH_LLAMA
bool preflight_dev_path(const std::string& path) {
    namespace fs = std::filesystem;
    if (path.empty() || path.size() > 4096 || path.find('\0') != std::string::npos) return false;
    const fs::path p(path);
    if (!p.is_absolute() || p.extension() != ".gguf") return false;
    std::error_code error;
    const auto meta = fs::symlink_status(p, error);
    if (error || !fs::is_regular_file(meta) || fs::is_symlink(meta)) return false;
    const auto n = fs::file_size(p, error);
    return !error && n > 0 && n <= kMaxDevModelBytes;
}

void fill_batch(llama_batch_ext* batch, const llama_token* tokens, int32_t count, llama_pos position) {
    llama_batch_ext_clear(batch);
    for (int32_t i = 0; i < count; ++i) {
        const int32_t index = llama_batch_ext_add_token(batch, 0, tokens[i]);
        const llama_pos pos = position + i;
        llama_batch_ext_set_pos(batch, index, &pos);
    }
    llama_batch_ext_set_output_logits(batch, count - 1, true);
}

// CPU ONLY. Native code is a development experiment; it is not sandboxed.
int run_cpu(const std::string& path, const std::string& prompt) {
    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    llama_model* model = llama_model_load_from_file(path.c_str(), mp);
    if (!model) { llama_backend_free(); return 4; }

    const llama_vocab* vocab = llama_model_get_vocab(model);
    const int n_required = -llama_tokenize(vocab, prompt.data(), prompt.size(), nullptr, 0, true, true);
    if (n_required <= 0 || n_required > static_cast<int>(kMaxModelContextTokens - kMaxGeneratedTokens)) {
        llama_model_free(model); llama_backend_free(); return 4;
    }
    std::vector<llama_token> tokens(static_cast<size_t>(n_required));
    const int n_prompt = llama_tokenize(vocab, prompt.data(), prompt.size(),
        tokens.data(), static_cast<int32_t>(tokens.size()), true, true);
    if (n_prompt <= 0 || n_prompt > static_cast<int>(tokens.size())) {
        llama_model_free(model); llama_backend_free(); return 4;
    }
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = kMaxModelContextTokens;
    cp.n_batch = kMaxModelContextTokens;
    cp.n_threads = 2;
    cp.n_threads_batch = 2;
    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) { llama_model_free(model); llama_backend_free(); return 4; }
    llama_sampler* sampler = llama_sampler_chain_init(llama_sampler_chain_default_params());
    if (!sampler) { llama_free(ctx); llama_model_free(model); llama_backend_free(); return 4; }
    llama_sampler_chain_add(sampler, llama_sampler_init_greedy());
    llama_batch_ext* batch = llama_batch_ext_init(ctx);
    if (!batch) {
        llama_sampler_free(sampler); llama_free(ctx); llama_model_free(model);
        llama_backend_free(); return 4;
    }
    if (!output_bytes("JENDGGUF1", 9)) return 5;
    fill_batch(batch, tokens.data(), n_prompt, 0);
    int pos = n_prompt;
    int status = 0;
    for (int n = 0; n < kMaxGeneratedTokens; ++n) {
        if (llama_process(ctx, LLAMA_PROCESS_TYPE_DECODE, batch) != 0) { status = 4; break; }
        const llama_token next = llama_sampler_sample(sampler, ctx, -1);
        if (llama_vocab_is_eog(vocab, next)) break;
        char piece[1024];
        const int len = llama_token_to_piece(vocab, next, piece, sizeof(piece), 0, true);
        if (len < 0 || len > static_cast<int>(sizeof(piece))
            || !send_frame('T', std::string(piece, static_cast<size_t>(len)))) {
            status = 4; break;
        }
        fill_batch(batch, &next, 1, pos++);
    }
    if (status == 0 && !send_frame('D', "")) status = 5;
    llama_batch_ext_free(batch);
    llama_sampler_free(sampler);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return status;
}
#endif
}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    // Native Windows CRT defaults to text mode. CRLF / 0x1A conversion
    // would corrupt length-delimited binary IPC and decoded token bytes.
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1) return 3;
#endif
    // Test-only probe: seccomp rules apply to the current process BEFORE
    // any worker IPC. Never reuse this branch for real GGUF inference.
    // Unsupported platforms and builds fail closed with no success marker.
    if (argc == 6 && std::strcmp(argv[1], "--sandbox-probe") == 0
        && std::strcmp(argv[2], "--deny-read") == 0
        && std::strcmp(argv[4], "--inherited-fd") == 0) {
#if defined(__linux__) && !defined(JEND_WITH_LLAMA)
        // Only synthetic test data; no real model, chat or private key.
        if (!argv[3] || argv[3][0] != '/' || access(argv[3], R_OK) != 0) return 3;
        int test_fd = -1;
        if (!jend_linux_probe::parse_expected_fd(argv[5], test_fd)) return 3;
        // Must verify and CLOSE the actually inherited descriptor before
        // attaching seccomp; remaining descriptors are exclusively stdio.
        if (!jend_linux_probe::strip_inherited_launch_state(test_fd)) return 3;
        if (!jend_linux_probe::install_restrictions()) return 3;
        if (!jend_linux_probe::verify_active_restrictions(argv[3], test_fd)) return 3;
        std::cout << "JEND-LINUX-RESTRICTED-PROBE-V1\n";
        return std::cout.flush() ? 0 : 5;
#else
        return 3;
#endif
    }
    if (argc == 2 && std::strcmp(argv[1], "--capabilities") == 0) {
#ifdef JEND_WITH_LLAMA
        std::cout << "JEND-GGUF-CPU-WORKER-V1 DEV_LLAMA\n";
#else
        std::cout << "JEND-GGUF-CPU-WORKER-V1 PROTOCOL_ONLY\n";
#endif
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--protocol-smoke") == 0) {
        std::string prompt;
        if (!read_prompt(prompt)) return 3;
        if (!output_bytes("JENDGGUF1", 9) || !send_frame('N', "NO_MODEL")) return 5;
        return 0;
    }
#ifdef JEND_WITH_LLAMA
    if (argc == 4 && std::strcmp(argv[1], "--infer-dev") == 0
        && std::strcmp(argv[2], "--model") == 0) {
        const char* opt = std::getenv("JEND_ENABLE_UNSANDBOXED_NATIVE_DEV_EXPERIMENT");
        if (!opt || std::strcmp(opt, "1") != 0) return 3;
        const std::string path(argv[3]);
        if (!preflight_dev_path(path)) return 3;
        std::string prompt;
        if (!read_prompt(prompt)) return 3;
        return run_cpu(path, prompt);
    }
#endif
    return 3;
}
