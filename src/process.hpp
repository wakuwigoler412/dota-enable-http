#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace patcher {

// Owns a handle to a dota2.exe process. Every fallible call returns
// std::expected with a message for the user.
class Process {
public:
    // A running dota2.exe. `error` then says why.
    struct Candidate {
        std::uint32_t pid{};
        std::string error;
    };

    struct Module {
        std::uintptr_t base{};
        std::uint32_t size{};
    };

    static std::expected<std::vector<Candidate>, std::string> list_dota();

    static std::expected<Process, std::string> open(std::uint32_t pid);

    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;
    ~Process();

    [[nodiscard]] std::expected<Module, std::string> find_server_dll() const;

    // Copies server.dll into a buffer where byte offset == RVA.
    [[nodiscard]] std::expected<std::vector<std::byte>, std::string>
    read_image(const Module& module) const;

    // Reads `out.size()` bytes; fails unless every byte is read.
    [[nodiscard]] std::expected<void, std::string>
    read(std::uintptr_t address, std::span<std::byte> out) const;

    // Writes code bytes: unprotects the range, writes, restores protection
    // and flushes the instruction cache.
    [[nodiscard]] std::expected<void, std::string>
    write_code(std::uintptr_t address, std::span<const std::byte> bytes) const;

private:
    explicit Process(void* handle) : handle_(handle) {}

    void* handle_ = nullptr;
};

} // namespace patcher
