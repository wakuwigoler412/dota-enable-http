// Dependency-free tests for the gate finder, run over synthetic images.
#include "gate.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <span>
#include <vector>

namespace {

int g_failures = 0;

void check(bool condition, const char* expr, int line) {
    if (!condition) {
        std::printf("FAIL line %d: %s\n", line, expr);
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

using Image = std::vector<std::byte>;

void put_bytes(Image& img, std::size_t at, std::initializer_list<std::uint8_t> bytes) {
    for (std::uint8_t b : bytes) img[at++] = std::byte{b};
}

template <typename T>
void put(Image& img, std::size_t at, T value) {
    std::memcpy(img.data() + at, &value, sizeof(value));
}

constexpr std::size_t kLoopOffset = 14;                    // after the two leas
constexpr std::size_t kBranch = kLoopOffset + 3;           // je within the loop

// Writes "lea rax,[table] / lea rdx,[table_end] / loop" at `code` and the id
// table at `table`. Returns the branch RVA.
std::uint32_t put_gate(Image& img, std::uint32_t code, std::uint32_t table,
                       std::span<const std::uint64_t> ids) {
    put_bytes(img, code, {0x48, 0x8D, 0x05});
    put<std::int32_t>(img, code + 3, static_cast<std::int32_t>(table - (code + 7)));
    put_bytes(img, code + 7, {0x48, 0x8D, 0x15});
    put<std::int32_t>(img, code + 10, static_cast<std::int32_t>(table + 5 * 8 - (code + 14)));
    put_bytes(img, code + kLoopOffset,
              {0x48, 0x39, 0x08, 0x74, 0x10, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x3B, 0xC2, 0x75, 0xF2});
    for (std::size_t i = 0; i < ids.size(); ++i) put(img, table + i * 8, ids[i]);
    return code + static_cast<std::uint32_t>(kBranch);
}

Image blank() { return Image(0x4000, std::byte{0xCC}); }

void finds_gate() {
    auto img = blank();
    const auto branch = put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    const auto gates = patcher::find_gates(img);
    CHECK(gates && gates->size() == 1 && gates->front() == branch);
}

void finds_two_gates() {
    auto img = blank();
    put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    put_gate(img, 0x1200, 0x2200, patcher::kWhitelistedIds);
    const auto gates = patcher::find_gates(img);
    CHECK(gates && gates->size() == 2);
}

void finds_already_patched_gate() {
    auto img = blank();
    const auto branch = put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    img[branch] = patcher::kJmp;
    const auto gates = patcher::find_gates(img);
    CHECK(gates && gates->size() == 1 && gates->front() == branch);
}

void finds_gate_with_nop_before_loop() {
    // Build 6980 has a nop between the leas and the loop.
    auto img = blank();
    put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    std::memmove(img.data() + 0x1000 + kLoopOffset + 1, img.data() + 0x1000 + kLoopOffset, 14);
    img[0x1000 + kLoopOffset] = std::byte{0x90};
    const auto gates = patcher::find_gates(img);
    CHECK(gates && gates->size() == 1 && gates->front() == 0x1000 + kBranch + 1);
}

void rejects_other_branch_opcode() {
    auto img = blank();
    const auto branch = put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    img[branch] = std::byte{0x90};
    CHECK(!patcher::find_gates(img));
}

void rejects_wrong_table() {
    auto img = blank();
    constexpr std::array<std::uint64_t, 5> wrong{1, 2, 3, 4, 5};
    put_gate(img, 0x1000, 0x2000, wrong);
    CHECK(!patcher::find_gates(img));
}

void finds_gate_with_two_known_ids() {
    // The whitelist may gain or lose entries; two known ids are enough.
    auto img = blank();
    const std::array<std::uint64_t, 5> ids{
        patcher::kWhitelistedIds[0], 0xAAAA, patcher::kWhitelistedIds[3], 0xBBBB, 0xCCCC};
    const auto branch = put_gate(img, 0x1000, 0x2000, ids);
    const auto gates = patcher::find_gates(img);
    CHECK(gates && gates->size() == 1 && gates->front() == branch);
}

void rejects_table_with_one_known_id() {
    auto img = blank();
    const std::array<std::uint64_t, 5> ids{patcher::kWhitelistedIds[0], 1, 2, 3, 4};
    put_gate(img, 0x1000, 0x2000, ids);
    CHECK(!patcher::find_gates(img));
}

void rejects_loop_without_lea() {
    auto img = blank();
    put_bytes(img, 0x1000,
              {0x48, 0x39, 0x08, 0x74, 0x10, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x3B, 0xC2, 0x75, 0xF2});
    CHECK(!patcher::find_gates(img));
}

void rejects_table_past_image_end() {
    auto img = blank();
    put_gate(img, 0x1000, 0x3FF0, {}); // table would run off the end
    CHECK(!patcher::find_gates(img));
}

void rejects_tiny_image() {
    CHECK(!patcher::find_gates(Image(4)));
}

// Build checks ("no GC lobby", "custom_game_id 0") ending right at
// `lea` (the gate's table lea, written by put_gate at the same address). Both
// jump to the loop's fall-through exit. Returns the RVA of the first byte.
std::uint32_t put_lobby_checks(Image& img, std::uint32_t lea, bool near_jumps) {
    const std::uint32_t deny = lea + static_cast<std::uint32_t>(kLoopOffset) + 14;
    const std::size_t je_size = near_jumps ? 6 : 2;
    const std::size_t size = 5 + 3 + je_size + 4 + 7 + 3 + je_size;
    std::size_t p = lea - size;
    const auto start = static_cast<std::uint32_t>(p);
    const auto put_je = [&](std::size_t at) {
        const std::size_t end = at + je_size;
        const auto rel = static_cast<std::int64_t>(deny) - static_cast<std::int64_t>(end);
        if (near_jumps) {
            put_bytes(img, at, {0x0F, 0x84});
            put<std::int32_t>(img, at + 2, static_cast<std::int32_t>(rel));
        } else {
            put_bytes(img, at, {0x74, static_cast<std::uint8_t>(static_cast<std::int8_t>(rel))});
        }
    };
    put_bytes(img, p, {0xE8, 0, 0, 0, 0, 0x48, 0x85, 0xC0});
    p += 8;
    put_je(p);
    p += je_size;
    put_bytes(img, p, {0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x88, 0x10, 0x02, 0x00, 0x00,
                       0x48, 0x85, 0xC9});
    p += 14;
    put_je(p);
    return start;
}

std::int64_t je_target(const patcher::Patch& p) {
    const auto& b = p.patched;
    if (b[0] == std::byte{0x74}) {
        return p.rva + 2 + static_cast<std::int8_t>(b[1]);
    }
    std::int32_t rel{};
    std::memcpy(&rel, b.data() + 2, sizeof(rel));
    return static_cast<std::int64_t>(p.rva) + 6 + rel;
}

void plain_gate_needs_only_whitelist_patch() {
    auto img = blank();
    put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    const auto patches = patcher::find_patches(img);
    CHECK(patches && patches->size() == 1 && patches->front().what == "whitelist");
}

void patches_lobby_checks(bool near_jumps) {
    auto img = blank();
    const auto branch = put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    put_lobby_checks(img, 0x1000, near_jumps);
    const std::int64_t allowed = branch + 2 + 0x10;

    const auto patches = patcher::find_patches(img);
    CHECK(patches && patches->size() == 3);
    if (!patches || patches->size() != 3) return;
    for (const auto& p : *patches) {
        CHECK(!p.applied());
        if (p.what != "whitelist") {
            CHECK(p.patched.size() == (near_jumps ? 6u : 2u));
            CHECK(je_target(p) == allowed);
        }
    }

    // Applying them yields an image where every patch reports applied.
    for (const auto& p : *patches) {
        std::memcpy(img.data() + p.rva, p.patched.data(), p.patched.size());
    }
    const auto again = patcher::find_patches(img);
    CHECK(again && again->size() == 3);
    if (again) {
        for (const auto& p : *again) CHECK(p.applied());
    }
}

void rejects_broken_lobby_lookup() {
    auto img = blank();
    put_gate(img, 0x1000, 0x2000, patcher::kWhitelistedIds);
    const auto start = put_lobby_checks(img, 0x1000, false);
    img[start] = std::byte{0x90}; // the lookup call is gone
    CHECK(!patcher::find_patches(img));
}

} // namespace

int main() {
    finds_gate();
    finds_two_gates();
    finds_already_patched_gate();
    finds_gate_with_nop_before_loop();
    rejects_other_branch_opcode();
    rejects_wrong_table();
    finds_gate_with_two_known_ids();
    rejects_table_with_one_known_id();
    rejects_loop_without_lea();
    rejects_table_past_image_end();
    rejects_tiny_image();
    plain_gate_needs_only_whitelist_patch();
    patches_lobby_checks(false);
    patches_lobby_checks(true);
    rejects_broken_lobby_lookup();

    if (g_failures == 0) {
        std::puts("all tests passed");
        return 0;
    }
    std::printf("%d check(s) failed\n", g_failures);
    return 1;
}
