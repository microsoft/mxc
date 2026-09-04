using System;
using System.Threading;

namespace Microsoft.Mxc.Diplomat.Diplomat;

#nullable enable

/// Frees a Rust-owned <typeparamref name="T"/> by calling its native destructor.
internal unsafe delegate void RustDestructor<T>(T* ptr) where T : unmanaged;

/// <summary>
/// Reference-counted native handle for one opaque. Starts at refcount 1 (the
/// owning wrapper). <see cref="Retain"/> hands a dependent a token; when the
/// count reaches zero this runs the native destructor first, then disposes
/// every edge — never the other way around.
/// </summary>
/// <remarks>
/// The refcount is updated with <see cref="Interlocked"/> so a user-thread
/// <see cref="Retain"/> can race a GC finalizer thread releasing another
/// dependent's token on the same handle without lost updates.
/// </remarks>
internal sealed unsafe class RustHandle<T> where T : unmanaged
{
    private T* _ptr;
    private readonly RustDestructor<T>? _destructor;
    private object[] _edges;
    private int _refCount = 1;

    private RustHandle(T* ptr, RustDestructor<T>? destructor, object[] edges)
    {
        _ptr = ptr;
        _destructor = destructor;
        _edges = edges;
    }

    /// The C# side owns the pointer and will run its destructor on release.
    internal static RustHandle<T> Owned(T* ptr, RustDestructor<T> destructor) =>
        new RustHandle<T>(ptr, destructor, System.Array.Empty<object>());

    /// Owned handle that also roots pins and/or retain tokens in <paramref name="edges"/>.
    internal static RustHandle<T> Owned(T* ptr, RustDestructor<T> destructor, object[] edges) =>
        new RustHandle<T>(ptr, destructor, edges);

    /// Rust still owns the pointer; release never runs a destructor.
    internal static RustHandle<T> Borrowed(T* ptr) =>
        new RustHandle<T>(ptr, null, System.Array.Empty<object>());

    /// Borrowed handle that also roots keep-alive edges.
    internal static RustHandle<T> Borrowed(T* ptr, object[] edges) =>
        new RustHandle<T>(ptr, null, edges);

    internal T* Ptr => _ptr;

    /// True once this handle's native pointer has been cleared (refcount hit zero,
    /// or a borrowed handle was never assigned).
    internal bool IsNull => _ptr is null;

    /// Bumps the count for one new direct dependent and returns its token.
    /// The caller must dispose the token exactly once from its own cleanup.
    internal IDisposable Retain()
    {
        while (true)
        {
            int current = Volatile.Read(ref _refCount);
            if (current == 0)
            {
                throw new ObjectDisposedException(typeof(T).Name);
            }

            if (Interlocked.CompareExchange(ref _refCount, current + 1, current) == current)
            {
                return new DependencyToken(this);
            }
        }
    }

    /// Releases this wrapper's own owner reference.
    internal void Release() => Decrement();

    private void Decrement()
    {
        if (Interlocked.Decrement(ref _refCount) != 0)
        {
            return;
        }

        T* ptr = _ptr;
        _ptr = null;
        if (ptr != null && _destructor is not null)
        {
            _destructor(ptr);
        }

        object[] edges = _edges;
        _edges = System.Array.Empty<object>();
        foreach (object edge in edges)
        {
            (edge as IDisposable)?.Dispose();
        }
    }

    /// One retained borrow-dependency token. A dependent holds one of these
    /// per direct source and disposes it exactly once from its own cleanup.
    private sealed class DependencyToken : IDisposable
    {
        private RustHandle<T>? _owner;

        internal DependencyToken(RustHandle<T> owner)
        {
            _owner = owner;
        }

        public void Dispose()
        {
            RustHandle<T>? owner = _owner;
            _owner = null;
            owner?.Decrement();
        }
    }
}