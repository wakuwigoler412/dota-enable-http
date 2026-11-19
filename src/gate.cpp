#include "gate.hpp"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <optional>

namespace patcher {
namespace {

// server.dll gates CreateHTTPRequest on the lobby's custom_game_id. When the id
// is nonzero it walks an .rdata table of allowed ids:
//
//   48 8D 05 rel32   lea rax, [table]
//   48 8D 15 rel32   lea rdx, [table_end]
//   (nop)            present on some builds
// loop:
//   48 39 08         cmp qword [rax], rcx     ; rcx = custom_game_id
//   74 ??            je  allowed              ; flipped to EB (jmp)
//   48 83 C0 08      add rax, 8
//   48 3B C2         cmp rax, rdx
//   75 F2            jne loop
//                    ; fall through = denied
//
// Normal games (id 0) never reach the loop, so forcing the je only affects
// custom games. Build 6980 has two such loops sharing one table; both are
// patched. The branch opcode is a wildcard so already-patched gates are found.
constexpr int kAny = -1;
constexpr std::array<int, 14> kLoop{
    0x48, 0x39, 0x08, kAny, kAny, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x3B, 0xC2, 0x75, 0xF2,
};
constexpr std::size_t kBranchOffset = 3;

// How far back from the loop to look for "lea rax, [table]". The leas take 14
// bytes; the rest is slack for padding such as the nop.
constexpr std::size_t kLeaWindow = 32;

bool loop_at(std::span<const std::byte> image, std::size_t pos) {
    for (std::size_t i = 0; i < kLoop.size(); ++i) {
        if (kLoop[i] != kAny && image[pos + i] != static_cast<std::byte>(kLoop[i])) {
            return false;
        }
    }
    return true;
}

template <typename T>
std::optional<T> read(std::span<const std::byte> image, std::size_t rva) {
    if (rva > image.size() || image.size() - rva < sizeof(T)) return std::nullopt;
    T value{};
    std::memcpy(&value, image.data() + rva, sizeof(T));
    return value;
}

struct Lea {
    std::size_t pos = 0;    // RVA of the lea instruction
    std::size_t target = 0; // RVA it loads
};

// The nearest "lea rax, [rip+rel32]" before the loop.
std::optional<Lea> find_lea(std::span<const std::byte> image, std::size_t loop_pos) {
    const std::size_t low = loop_pos > kLeaWindow ? loop_pos - kLeaWindow : 0;
    for (std::size_t p = loop_pos; p-- > low;) {
        if (image[p] == std::byte{0x48} && image[p + 1] == std::byte{0x8D} &&
            image[p + 2] == std::byte{0x05}) {
            const auto rel = read<std::int32_t>(image, p + 3);
            if (!rel) return std::nullopt;
            const auto target = static_cast<std::int64_t>(p) + 7 + *rel;
            if (target < 0) return std::nullopt;
            return Lea{p, static_cast<std::size_t>(target)};
        }
    }
    return std::nullopt;
}

bool bytes_at(std::span<const std::byte> image, std::size_t pos,
              std::initializer_list<std::uint8_t> expected) {
    if (pos > image.size() || image.size() - pos < expected.size()) return false;
    std::size_t i = pos;
    for (const std::uint8_t b : expected) {
        if (image[i++] != std::byte{b}) return false;
    }
    return true;
}

// A conditional "je" that ends at `end`: short (74 rel8) or near (0F 84 rel32).
struct Je {
    std::size_t pos = 0;
    std::size_t end = 0;
    bool is_near = false;
    std::int64_t target = 0;
};

std::optional<Je> je_ending_at(std::span<const std::byte> image, std::size_t end) {
    if (end >= 2 && image[end - 2] == std::byte{0x74}) {
        const auto rel = static_cast<std::int8_t>(image[end - 1]);
        return Je{end - 2, end, false, static_cast<std::int64_t>(end) + rel};
    }
    if (end >= 6 && bytes_at(image, end - 6, {0x0F, 0x84})) {
        const auto rel = read<std::int32_t>(image, end - 4);
        if (!rel) return std::nullopt;
        return Je{end - 6, end, true, static_cast<std::int64_t>(end) + *rel};
    }
    return std::nullopt;
}

// Bytes of a je at `je.pos` (same size) that jumps to `to`, or nullopt when
// a short je cannot reach it.
std::optional<std::vector<std::byte>> retarget(const Je& je, std::size_t to) {
    const std::int64_t rel = static_cast<std::int64_t>(to) - static_cast<std::int64_t>(je.end);
    if (!je.is_near) {
        if (rel < -128 || rel > 127) return std::nullopt;
        return std::vector<std::byte>{std::byte{0x74},
                                      static_cast<std::byte>(static_cast<std::int8_t>(rel))};
    }
    std::vector<std::byte> out{std::byte{0x0F}, std::byte{0x84}, {}, {}, {}, {}};
    const auto rel32 = static_cast<std::int32_t>(rel);
    std::memcpy(out.data() + 2, &rel32, sizeof(rel32));
    return out;
}

std::vector<std::byte> slice(std::span<const std::byte> image, std::size_t pos, std::size_t n) {
    return {image.begin() + static_cast<std::ptrdiff_t>(pos),
            image.begin() + static_cast<std::ptrdiff_t>(pos + n)};
}

// Build 6980 puts two checks right in front of the table lea:
//
//   E8 rel32               call find_lobby          ; fallback lookup
//   48 85 C0               test rax, rax
//   je deny                                          ; no GC lobby
//   48 8B 40 ??            mov rax, [rax+??]
//   48 8B 88 rel32         mov rcx, [rax+??]         ; custom_game_id
//   48 85 C9               test rcx, rcx
//   je deny                                          ; id 0
//   48 8D 05 ...           lea rax, [table]
//
// The integrated server of Workshop Tools has no GC lobby, so it is denied
// before the whitelist is reached. Returns the two jes, nearest first, or an
// empty vector when the build has no such checks.
std::expected<std::vector<Je>, std::string>
lobby_checks(std::span<const std::byte> image, std::size_t lea_pos,
             const std::vector<std::int64_t>& deny, std::size_t allowed) {
    const auto goes_to_gate_exit = [&](const Je& je) {
        return je.target == static_cast<std::int64_t>(allowed) ||
               std::ranges::find(deny, je.target) != deny.end();
    };

    const auto id_check = je_ending_at(image, lea_pos);
    if (!id_check || !goes_to_gate_exit(*id_check)) return std::vector<Je>{};
    std::size_t p = id_check->pos;
    if (p < 3 + 7 + 4 || !bytes_at(image, p - 3, {0x48, 0x85, 0xC9})) return std::vector<Je>{};
    p -= 3;
    if (!bytes_at(image, p - 7, {0x48, 0x8B, 0x88})) return std::vector<Je>{};
    p -= 7;
    if (!bytes_at(image, p - 4, {0x48, 0x8B, 0x40})) return std::vector<Je>{};
    p -= 4;

    // From here on the shape is the 6980 one; anything off is an error rather
    // than a silent skip, since the whitelist patch alone would not work.
    const auto lobby_check = je_ending_at(image, p);
    if (!lobby_check || !goes_to_gate_exit(*lobby_check)) {
        return std::unexpected("lobby check before the HTTP gate has an unexpected shape");
    }
    p = lobby_check->pos;
    if (p < 3 + 5 || !bytes_at(image, p - 3, {0x48, 0x85, 0xC0}) ||
        image[p - 3 - 5] != std::byte{0xE8}) {
        return std::unexpected("lobby lookup before the HTTP gate has an unexpected shape");
    }
    return std::vector<Je>{*id_check, *lobby_check};
}

// The lea before the loop points at the table of allowed custom_game_ids. We
// recognise it by how many known ids it still holds, not by an exact match, so
// the whitelist gaining or losing entries across builds does not hide the gate.
// Two matches keep an unrelated qword table from passing (the ids are unique).
constexpr std::size_t kMinWhitelistMatches = 2;
constexpr std::size_t kMaxTableScan = 16;

bool is_whitelist_table(std::span<const std::byte> image, std::size_t rva) {
    std::size_t matches = 0;
    for (std::size_t i = 0; i < kMaxTableScan; ++i) {
        const auto value = read<std::uint64_t>(image, rva + i * sizeof(std::uint64_t));
        if (!value) break;
        if (std::ranges::find(kWhitelistedIds, *value) != kWhitelistedIds.end() &&
            ++matches >= kMinWhitelistMatches) {
            return true;
        }
    }
    return false;
}

} // namespace

std::expected<std::vector<std::uint32_t>, std::string>
find_gates(std::span<const std::byte> image) {
    std::vector<std::uint32_t> gates;
    if (image.size() < kLoop.size()) return std::unexpected("server.dll image is empty");

    for (std::size_t pos = 0; pos + kLoop.size() <= image.size(); ++pos) {
        if (!loop_at(image, pos)) continue;
        const std::byte branch = image[pos + kBranchOffset];
        if (branch != kJe && branch != kJmp) continue;
        const auto lea = find_lea(image, pos);
        if (!lea || !is_whitelist_table(image, lea->target)) continue;
        gates.push_back(static_cast<std::uint32_t>(pos + kBranchOffset));
    }

    if (gates.empty()) {
        return std::unexpected("HTTP whitelist gate not found in server.dll "
                               "(unsupported Dota build?)");
    }
    return gates;
}

std::expected<std::vector<Patch>, std::string> find_patches(std::span<const std::byte> image) {
    const auto gates = find_gates(image);
    if (!gates) return std::unexpected(gates.error());

    std::vector<Patch> patches;
    for (const std::uint32_t branch : *gates) {
        const std::size_t loop = branch - kBranchOffset;
        const auto rel8 = static_cast<std::int8_t>(image[branch + 1]);
        const std::size_t allowed = branch + 2 + rel8;

        // Denied = falling out of the loop, possibly via a jmp to a shared exit.
        const std::size_t loop_end = loop + kLoop.size();
        std::vector<std::int64_t> deny{static_cast<std::int64_t>(loop_end)};
        if (loop_end + 2 <= image.size() && image[loop_end] == std::byte{0xEB}) {
            deny.push_back(static_cast<std::int64_t>(loop_end) + 2 +
                           static_cast<std::int8_t>(image[loop_end + 1]));
        } else if (const auto rel = read<std::int32_t>(image, loop_end + 1);
                   rel && image[loop_end] == std::byte{0xE9}) {
            deny.push_back(static_cast<std::int64_t>(loop_end) + 5 + *rel);
        }

        patches.push_back({branch, slice(image, branch, 1), {kJmp}, "whitelist"});

        const auto lea = find_lea(image, loop);
        if (!lea) continue; // find_gates verified it; unreachable
        const auto checks = lobby_checks(image, lea->pos, deny, allowed);
        if (!checks) return std::unexpected(checks.error());
        const char* names[] = {"custom_game_id 0", "no GC lobby"};
        for (std::size_t i = 0; i < checks->size(); ++i) {
            const Je& je = (*checks)[i];
            auto bytes = retarget(je, allowed);
            if (!bytes) return std::unexpected("lobby check is too far from the gate to retarget");
            patches.push_back({static_cast<std::uint32_t>(je.pos),
                               slice(image, je.pos, je.end - je.pos), std::move(*bytes),
                               names[i]});
        }
    }
    return patches;
}

} // namespace patcher
