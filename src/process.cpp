#include "process.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <format>
#include <utility>

namespace patcher {
namespace {

std::string last_error(std::string_view what) {
    return std::format("{} (GetLastError={})", what, ::GetLastError());
}

// Closes a Win32 handle on scope exit.
struct ScopedHandle {
    HANDLE h;
    explicit ScopedHandle(HANDLE handle) : h(handle) {}
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ~ScopedHandle() {
        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
};

bool iequals(std::wstring_view a, std::wstring_view b) {
    return std::ranges::equal(a, b, [](wchar_t x, wchar_t y) {
        return std::towlower(x) == std::towlower(y);
    });
}

// Lets an elevated tool open Dota even when it runs as another user. Failure is
// harmless: OpenProcess then reports the real error.
void enable_debug_privilege() {
    HANDLE raw{};
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &raw)) return;
    const ScopedHandle token{raw};
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ::AdjustTokenPrivileges(token.h, FALSE, &tp, 0, nullptr, nullptr);
    }
}

std::expected<std::vector<DWORD>, std::string> find_dota_pids() {
    const ScopedHandle snap{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snap.h == INVALID_HANDLE_VALUE) return std::unexpected(last_error("process snapshot failed"));
    PROCESSENTRY32W entry{.dwSize = sizeof(PROCESSENTRY32W)};
    std::vector<DWORD> pids;
    for (BOOL ok = ::Process32FirstW(snap.h, &entry); ok; ok = ::Process32NextW(snap.h, &entry)) {
        if (iequals(entry.szExeFile, L"dota2.exe")) pids.push_back(entry.th32ProcessID);
    }
    if (pids.empty()) return std::unexpected("dota2.exe is not running");
    return pids;
}

} // namespace

std::expected<std::vector<Process::Candidate>, std::string> Process::list_dota() {
    const auto pids = find_dota_pids();
    if (!pids) return std::unexpected(pids.error());

    std::vector<Candidate> candidates;
    for (const DWORD pid : *pids) {
        Candidate c{.pid = pid};
        if (auto p = open(pid); !p) {
            c.error = p.error();
        }
        candidates.push_back(std::move(c));
    }
    return candidates;
}

std::expected<Process, std::string> Process::open(std::uint32_t pid) {
    static const bool privilege_tried = (enable_debug_privilege(), true);
    (void)privilege_tried;

    constexpr DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                             PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    HANDLE h = ::OpenProcess(access, FALSE, pid);
    if (!h) {
        return std::unexpected(last_error(std::format(
            "could not open pid {} (run elevated if Dota is elevated)", pid)));
    }
    return Process{h};
}

Process::Process(Process&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        if (handle_) ::CloseHandle(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

Process::~Process() {
    if (handle_) ::CloseHandle(handle_);
}

std::expected<void, std::string> Process::read(std::uintptr_t address,
                                               std::span<std::byte> out) const {
    SIZE_T done = 0;
    if (!::ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), out.data(),
                             out.size(), &done) ||
        done != out.size()) {
        return std::unexpected(last_error("ReadProcessMemory failed"));
    }
    return {};
}

std::expected<Process::Module, std::string> Process::find_server_dll() const {
    // The snapshot can fail with ERROR_BAD_LENGTH while the target loads
    // modules; retry a few times.
    ScopedHandle snap{INVALID_HANDLE_VALUE};
    for (int attempt = 0; attempt < 5 && snap.h == INVALID_HANDLE_VALUE; ++attempt) {
        snap.h = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ::GetProcessId(handle_));
        if (snap.h == INVALID_HANDLE_VALUE && ::GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (snap.h == INVALID_HANDLE_VALUE) return std::unexpected(last_error("module snapshot failed"));
    MODULEENTRY32W entry{.dwSize = sizeof(MODULEENTRY32W)};
    Module module{};
    for (BOOL ok = ::Module32FirstW(snap.h, &entry); ok; ok = ::Module32NextW(snap.h, &entry)) {
        if (iequals(entry.szModule, L"server.dll")) {
            module = {reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize};
            break;
        }
    }
    if (module.base == 0) return std::unexpected("server.dll is not loaded (host a map first)");
    return module;
}

std::expected<std::vector<std::byte>, std::string>
Process::read_image(const Module& module) const {
    std::array<std::byte, 0x1000> headers{};
    if (auto r = read(module.base, headers); !r) return std::unexpected(r.error());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > headers.size()) {
        return std::unexpected("server.dll: bad DOS header");
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return std::unexpected("server.dll: bad NT header");

    const std::uint32_t image_size = nt->OptionalHeader.SizeOfImage;
    if (image_size != module.size) {
        return std::unexpected("server.dll: SizeOfImage disagrees with loaded size");
    }
    const auto* first = IMAGE_FIRST_SECTION(nt);
    const std::uint16_t count = nt->FileHeader.NumberOfSections;
    if (reinterpret_cast<const std::byte*>(first + count) > headers.data() + headers.size()) {
        return std::unexpected("server.dll: section table exceeds headers");
    }

    // Sections are copied to their RVAs; gaps between them stay zero.
    std::vector<std::byte> image(image_size);
    for (const auto& section : std::span{first, count}) {
        const std::uint32_t rva = section.VirtualAddress;
        const std::uint32_t size = section.Misc.VirtualSize;
        if (size == 0) continue;
        if (static_cast<std::uint64_t>(rva) + size > image_size) {
            return std::unexpected("server.dll: section exceeds image bounds");
        }
        if (auto r = read(module.base + rva, {image.data() + rva, size}); !r) {
            return std::unexpected(r.error());
        }
    }
    return image;
}

std::expected<void, std::string> Process::write_code(std::uintptr_t address,
                                                     std::span<const std::byte> bytes) const {
    const auto target = reinterpret_cast<LPVOID>(address);
    const SIZE_T size = bytes.size();
    DWORD old_protect = 0;
    if (!::VirtualProtectEx(handle_, target, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return std::unexpected(last_error("VirtualProtectEx failed"));
    }

    SIZE_T written = 0;
    const bool ok =
        ::WriteProcessMemory(handle_, target, bytes.data(), size, &written) && written == size;
    const std::string error = ok ? std::string{} : last_error("WriteProcessMemory failed");

    DWORD ignored = 0;
    ::VirtualProtectEx(handle_, target, size, old_protect, &ignored);
    if (!ok) return std::unexpected(error);

    ::FlushInstructionCache(handle_, target, size);
    return {};
}

} // namespace patcher
