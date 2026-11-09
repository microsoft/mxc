# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# HTTP listener bound only to Windows 127.0.0.1 that answers every request with
# a per-run token. Dot-source this file, then pair Start- with Stop-.

function Start-LoopbackTokenServer {
    $token = "HOST_LOOPBACK_" + [guid]::NewGuid().ToString("N")
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()

    $shell = [powershell]::Create().AddScript({
        param($listener, $token)
        $body = [Text.Encoding]::ASCII.GetBytes($token)
        $header = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.0 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
        try {
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 5000
                    $buffer = New-Object byte[] 4096
                    $null = $stream.Read($buffer, 0, $buffer.Length)
                    $stream.Write($header, 0, $header.Length)
                    $stream.Write($body, 0, $body.Length)
                } catch {
                } finally {
                    $client.Close()
                }
            }
        } catch {
            # AcceptTcpClient throws once the listener stops.
        }
    }).AddArgument($listener).AddArgument($token)

    @{
        Port     = $listener.LocalEndpoint.Port
        Token    = $token
        Listener = $listener
        Shell    = $shell
        Run      = $shell.BeginInvoke()
    }
}

function Stop-LoopbackTokenServer {
    param($Server)
    if (-not $Server) { return }
    $Server.Listener.Stop()
    $null = $Server.Run.AsyncWaitHandle.WaitOne(5000)
    $Server.Shell.Dispose()
}
