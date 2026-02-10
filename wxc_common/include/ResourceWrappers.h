#pragma once

#include <Windows.h>

#include <memory>

namespace WXC
{

// RAII wrapper for Windows HANDLEs
struct HandleDeleter
{
    using pointer = HANDLE;
    void operator()(pointer h) const noexcept
    {
        if (h && h != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(h);
        }
    }
};
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

// RAII wrapper for SIDs allocated with FreeSid
struct SidDeleter
{
    using pointer = PSID;
    void operator()(pointer sid) const noexcept
    {
        if (sid)
        {
            ::FreeSid(sid);
        }
    }
};
using UniqueSid = std::unique_ptr<std::remove_pointer_t<PSID>, SidDeleter>;

// RAII wrapper for LocalFree
struct LocalFreeDeleter
{
    using pointer = void*;
    void operator()(pointer ptr) const noexcept
    {
        if (ptr)
        {
            ::LocalFree(ptr);
        }
    }
};
using UniqueLocalAlloc = std::unique_ptr<void, LocalFreeDeleter>;

// RAII wrapper for HeapAlloc
struct HeapDeleter
{
    using pointer = void*;
    void operator()(pointer ptr) const noexcept
    {
        if (ptr)
        {
            ::HeapFree(::GetProcessHeap(), 0, ptr);
        }
    }
};
using UniqueHeapAlloc = std::unique_ptr<void, HeapDeleter>;

// RAII wrapper for PROC_THREAD_ATTRIBUTE_LIST
class AttributeListGuard
{
public:
    explicit AttributeListGuard(LPPROC_THREAD_ATTRIBUTE_LIST list)
        : _list(list)
        , _initialized(false)
    {
    }

    void MarkInitialized() noexcept { _initialized = true; }

    ~AttributeListGuard()
    {
        if (_initialized && _list)
        {
            ::DeleteProcThreadAttributeList(_list);
        }
    }

    // Prevent copying
    AttributeListGuard(const AttributeListGuard&) = delete;
    AttributeListGuard& operator=(const AttributeListGuard&) = delete;

private:
    LPPROC_THREAD_ATTRIBUTE_LIST _list;
    bool _initialized;
};

} // namespace WXC
