#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace patcher {

// custom_game_id values server.dll lets create VScript HTTP requests. A gate is
// accepted when the table it walks still holds at least two of these, so the
// whitelist changing across builds does not hide the gate.
inline constexpr std::array<std::uint64_t, 5> kWhitelistedIds{
    469311655ULL,   // Roshpit Champions
    626780182ULL,   // Element TD
    520323982ULL,   // 荒神罪
    473718711ULL,   // Crumbling Island Arena
    1613886175ULL,  // Dota Auto Chess
};

inline constexpr std::byte kJe{0x74};  // original: allowed only if the id is listed
inline constexpr std::byte kJmp{0xEB}; // patched: every custom game allowed

// Finds the whitelist gates in a server.dll image laid out at its RVAs (buffer
// offset == RVA). Returns the RVA of each gate's branch byte, which is kJe, or
// kJmp when already patched. Errors when no gate with a verified table exists.
[[nodiscard]] std::expected<std::vector<std::uint32_t>, std::string>
find_gates(std::span<const std::byte> image);

// One code change. `current` is what the image holds now; `patched` is what
// it should hold. When they are equal the change is already applied.
struct Patch {
    std::uint32_t rva = 0;
    std::vector<std::byte> current;
    std::vector<std::byte> patched;
    std::string what;

    [[nodiscard]] bool applied() const { return current == patched; }
};

// Every change needed to allow VScript HTTP for all games:
//   * the whitelist branch of each gate (je -> jmp);
//   * since build 6980, the two lobby checks in front of each gate's table
//     walk: "no GC lobby" and "custom_game_id == 0" now deny, which blocks the
//     integrated (listen) server of Workshop Tools. Both are retargeted to the
//     gate's "allowed" label. Builds without these checks get only the
//     whitelist patches.
// Errors when no verified gate exists or a lobby check cannot be retargeted.
[[nodiscard]] std::expected<std::vector<Patch>, std::string>
find_patches(std::span<const std::byte> image);

} // namespace patcher
