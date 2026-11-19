#include "gate.hpp"
#include "process.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef APP_VERSION
#define APP_VERSION "0.0.0-dev"
#endif

namespace {

using patcher::Process;

constexpr int kExitOk = 0;
constexpr int kExitError = 1;
constexpr int kExitUsage = 2;
constexpr int kExitMultiple = 3; // several dota2.exe, --headless and no --pid

struct Options {
    bool dry_run = false;
    bool headless = false;
    std::optional<std::uint32_t> pid;
};

constexpr char kUsage[] =
    "Usage: dota-enable-http [options]\n"
    "Enables VScript HTTP (CreateHTTPRequest) for every custom game in a running Dota.\n"
    "\n"
    "  --dry-run          find the gates, change nothing\n"
    "  --pid <pid>        target one dota2.exe\n"
    "  --headless         no prompts or pause; exit 3 if several dota2.exe and no --pid\n"
    "  --help             show this help\n";

int fail(std::string_view message) {
    std::fprintf(stderr, "error: %.*s\n", static_cast<int>(message.size()), message.data());
    return kExitError;
}

// One line from stdin without its line ending; nullopt on EOF.
std::optional<std::string> read_line() {
    std::string line;
    for (int c = std::getchar(); c != EOF; c = std::getchar()) {
        if (c == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        line += static_cast<char>(c);
    }
    if (line.empty()) return std::nullopt;
    return line;
}

template <typename T>
std::optional<T> parse_number(std::string_view s) {
    while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
    while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
    T value{};
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (s.empty() || ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
    return value;
}

void print_candidates(const std::vector<Process::Candidate>& candidates, bool numbered) {
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        const std::string index = numbered ? std::format("[{}] ", i + 1) : "";
        std::printf("  %spid %u\n", index.c_str(), c.pid);
    }
}

// The pid to patch, or the exit code to stop with.
std::expected<std::uint32_t, int> select_pid(const Options& opts) {
    const auto candidates = Process::list_dota();
    if (!candidates) return std::unexpected(fail(candidates.error()));

    if (opts.pid) {
        const bool found = std::ranges::any_of(
            *candidates, [&](const auto& c) { return c.pid == *opts.pid; });
        if (!found) {
            return std::unexpected(fail(std::format("pid {} is not a running dota2.exe", *opts.pid)));
        }
        return *opts.pid;
    }
    if (candidates->size() == 1) return candidates->front().pid;

    std::printf("Found %zu dota2.exe processes:\n", candidates->size());
    if (opts.headless) {
        print_candidates(*candidates, false);
        std::puts("Pick one with --pid.");
        return std::unexpected(kExitMultiple);
    }
    print_candidates(*candidates, true);
    for (;;) {
        std::printf("Select 1-%zu (q to cancel): ", candidates->size());
        std::fflush(stdout);
        const auto line = read_line();
        if (!line || *line == "q" || *line == "Q") return std::unexpected(fail("cancelled"));
        const auto n = parse_number<std::size_t>(*line);
        if (n && *n >= 1 && *n <= candidates->size()) return (*candidates)[*n - 1].pid;
    }
}

int run(const Options& opts) {
    const auto pid = select_pid(opts);
    if (!pid) return pid.error();

    const auto process = Process::open(*pid);
    if (!process) return fail(process.error());

    const auto module = process->find_server_dll();
    if (!module) return fail(module.error());
    const auto image = process->read_image(*module);
    if (!image) return fail(image.error());
    const auto patches = patcher::find_patches(*image);
    if (!patches) return fail(patches.error());

    // Verify everything against live memory before writing anything.
    for (const auto& p : *patches) {
        std::vector<std::byte> live(p.current.size());
        if (auto r = process->read(module->base + p.rva, live); !r) return fail(r.error());
        if (live != p.current) {
            return fail(std::format("code at server.dll+{:#x} changed while reading; nothing written",
                                    p.rva));
        }
    }

    int patched = 0;
    int already = 0;
    for (const auto& p : *patches) {
        if (p.applied()) {
            ++already;
            continue;
        }
        if (!opts.dry_run) {
            if (auto w = process->write_code(module->base + p.rva, p.patched); !w) {
                return fail(w.error());
            }
        }
        std::printf("  server.dll+%#x  %s\n", p.rva, p.what.c_str());
        ++patched;
    }

    if (opts.dry_run) {
        std::printf("pid %u: %d change(s) would be made, %d already patched.\n", *pid, patched,
                    already);
    } else {
        std::printf("pid %u: HTTP enabled (%d change(s) made, %d already applied).\n", *pid,
                    patched, already);
        std::puts("The change lasts until Dota exits. Relaunch Dota to undo it.");
    }
    return kExitOk;
}

// Fills `opts`; returns an exit code when the program should stop right away.
std::optional<int> parse_args(std::span<char*> args, Options& opts) {
    // Read first so a bad argument still respects it.
    opts.headless = std::ranges::any_of(
        args, [](const char* a) { return std::string_view{a} == "--headless"; });

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view arg = args[i];
        if (arg == "--help" || arg == "-h") {
            std::fputs(kUsage, stdout);
            return kExitOk;
        }
        if (arg == "--version" || arg == "-V") {
            std::puts("dota-enable-http " APP_VERSION);
            return kExitOk;
        }
        if (arg == "--dry-run") {
            opts.dry_run = true;
        } else if (arg == "--pid") {
            const auto pid = i + 1 < args.size() ? parse_number<std::uint32_t>(args[++i])
                                                 : std::nullopt;
            if (!pid || *pid == 0) {
                std::fprintf(stderr, "--pid needs a process id\n\n%s", kUsage);
                return kExitUsage;
            }
            opts.pid = *pid;
        } else if (arg != "--headless") {
            std::fprintf(stderr, "unknown argument: %s\n\n%s", args[i], kUsage);
            return kExitUsage;
        }
    }
    return std::nullopt;
}

} // namespace

int main(int argc, char** argv) {
    Options opts;
    const std::size_t argn = argc > 0 ? static_cast<std::size_t>(argc - 1) : 0;
    const auto early = parse_args(std::span{argv + (argc > 0 ? 1 : 0), argn}, opts);
    const int code = early ? *early : run(opts);
    if (!opts.headless) {
        std::fputs("\nPress Enter to exit...", stdout);
        std::fflush(stdout);
        (void)read_line();
    }
    return code;
}
