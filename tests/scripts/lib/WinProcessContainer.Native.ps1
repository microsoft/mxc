# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Native helper types for the Windows process-container suite. Dot-sourced
# only by the two scripts that need them (the UI-mitigation matrix and the
# global-atom isolation test) — compiling these on every child script would
# add a second or two to each of the nineteen processes for nothing.

# kernel32 atom-table P/Invoke used by Phase-GlobalAtomIsolation to plant a
# host-side global atom (direction 1) and to probe its own session-global
# table for the contained process's atom (direction 2). Guarded so a re-run
# in the same PowerShell session doesn't throw "type already exists".
if (-not ([System.Management.Automation.PSTypeName]'Mxc.AtomNative').Type) {
    Add-Type -Namespace 'Mxc' -Name 'AtomNative' -MemberDefinition @'
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ushort GlobalAddAtomW(string lpString);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ushort GlobalFindAtomW(string lpString);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern ushort GlobalDeleteAtom(ushort nAtom);
'@ | Out-Null
}

# A hidden, message-pumping top-level window owned by the harness process —
# used by Phase 4b's HANDLES probe as a USER handle owned by a process OUTSIDE
# the job. The window runs its message loop on a dedicated background thread so
# a cross-job GetWindowTextW (WM_GETTEXT) is answered promptly in the (broken)
# case where the JOB_OBJECT_UILIMIT_HANDLES limit fails to block it.
if (-not ([System.Management.Automation.PSTypeName]'Mxc.WindowHost').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Mxc {
    public class WindowHost {
        [StructLayout(LayoutKind.Sequential)]
        private struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int ptX; public int ptY; }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(int dwExStyle, string lpClassName, string lpWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        private static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);
        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessageW(ref MSG lpMsg);
        [DllImport("user32.dll")]
        private static extern bool PostThreadMessageW(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        private const uint WM_QUIT = 0x0012;
        private const int WS_EX_TOOLWINDOW = 0x00000080;

        private Thread _thread;
        private uint _threadId;
        private volatile IntPtr _hwnd = IntPtr.Zero;
        private readonly ManualResetEventSlim _ready = new ManualResetEventSlim(false);
        private string _title;

        public IntPtr Hwnd { get { return _hwnd; } }
        public string Title { get { return _title; } }

        public void Start(string title) {
            _title = title;
            _thread = new Thread(Run);
            _thread.IsBackground = true;
            _thread.Start();
            if (!_ready.Wait(5000)) { throw new Exception("WindowHost: window creation timed out"); }
            if (_hwnd == IntPtr.Zero) { throw new Exception("WindowHost: CreateWindowExW failed"); }
        }

        private void Run() {
            _threadId = GetCurrentThreadId();
            // The system "STATIC" class needs no registration; omitting
            // WS_VISIBLE keeps the window hidden. The window just needs to be a
            // valid HWND owned by this (out-of-job) process for the HANDLES
            // probe's GetWindowThreadProcessId to resolve.
            _hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, "STATIC", _title, 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            _ready.Set();
            if (_hwnd == IntPtr.Zero) { return; }
            MSG msg;
            // Pump the queue to keep this thread (and thus the window) alive
            // until Stop() posts WM_QUIT. GetMessageW returns 0 on WM_QUIT and
            // -1 on error; exit on both.
            while (GetMessageW(out msg, IntPtr.Zero, 0, 0) > 0) {
                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
            DestroyWindow(_hwnd);
        }

        public void Stop() {
            if (_thread == null) { return; }
            if (_threadId != 0) { PostThreadMessageW(_threadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); }
            _thread.Join(3000);
        }
    }
}
'@ | Out-Null
}

# -----------------------------------------------------------------------
# Result accumulator
# -----------------------------------------------------------------------
