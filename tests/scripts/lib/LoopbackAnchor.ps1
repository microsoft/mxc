# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# LoopbackAnchor.ps1 — host-side loopback HTTP anchor for IsolationSession
# network tests.
#
# An isolated session is a separate OS logon session on the same machine, so a
# host loopback listener is reachable from inside it. Anchoring the positive
# network oracle here keeps it hermetic: it asserts the session's network
# posture rather than the runner's outbound internet access.

# Binds an ephemeral loopback port and serves a fixed body from a background
# runspace, so the caller can stay blocked on a sandbox exec while the
# contained process connects back. Returns $null if the port cannot be bound.
function Start-LoopbackAnchor {
    # Bind port 0 and read back what the OS assigned, rather than reserving a
    # port up front and re-binding it: another process can take the port in
    # between, and the anchor then answers on a socket nobody can reach.
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
    } catch {
        return $null
    }
    $port = $listener.LocalEndpoint.Port
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($l)
        $body = 'MXC-ISO-LOOPBACK-ANCHOR'
        $response = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
        while ($true) {
            try {
                $client = $l.AcceptTcpClient()
                $stream = $client.GetStream()
                # Read whatever request line the client sent before replying;
                # curl will not report success if the peer resets first.
                $stream.ReadTimeout = 2000
                $buf = New-Object byte[] 1024
                try { [void]$stream.Read($buf, 0, $buf.Length) } catch {}
                $stream.Write($response, 0, $response.Length)
                $stream.Flush()
                $client.Close()
            } catch { break }
        }
    }).AddArgument($listener)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{
        Port = $port
        Url  = "http://127.0.0.1:$port/"
        Body = 'MXC-ISO-LOOPBACK-ANCHOR'
        Stop = {
            try { $listener.Stop() } catch {}
            try { [void]$ps.EndInvoke($handle) } catch {}
            try { $ps.Dispose() } catch {}
        }.GetNewClosure()
    }
}

function Stop-LoopbackAnchor {
    param($Anchor)
    if ($null -eq $Anchor) { return }
    & $Anchor.Stop
}

# Command line that fetches the anchor from inside a sandbox.
#
# Deliberately a bare curl rather than a `&& echo REACHED || echo BLOCKED`
# token pair: the one-shot runner invokes wxc-exec with --debug, which echoes
# the command line, so any verdict token spelled here would appear in the
# captured output whether or not the probe ran. The anchor's response body
# cannot be echoed that way, which makes it the only honest oracle -- and
# curl's non-zero exit on a failed connect covers the negative side.
function Get-LoopbackAnchorCommand {
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TimeoutSec = 15
    )
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    "$curl --silent --show-error --fail --noproxy * --max-time $TimeoutSec $Url"
}
