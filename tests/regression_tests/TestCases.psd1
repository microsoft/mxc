@{
    "473" = @{
        FriendlyName = "Packaged App Launch"
        Script = "test_cases\Invoke-Issue473-PackagedApp.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec", "MSIX packaged Notepad")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "483" = @{
        FriendlyName = "Bun Runtime Launch"
        Script = "test_cases\Invoke-Issue483-BunAndSparsePath.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec", "Bun")
        Dependencies = @(
            @{
                Name = "Bun"
                Executable = "bun.exe"
                WingetId = "Oven-sh.Bun"
                ArgumentName = "BunExe"
            }
        )
        HarnessArguments = "Default"
        Destructive = $false
    }
    "636" = @{
        FriendlyName = "Edge Isolated Startup"
        Script = "test_cases\Invoke-Issue636-EdgeStartup.ps1"
        ExpectedTierSupport = @("appcontainer-dacl")
        Prerequisites = @("wxc-exec", "Microsoft Edge", "interactive desktop")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "648" = @{
        FriendlyName = "Host ACL Propagation"
        Script = "test_cases\Invoke-Issue648-DESTRUCTIVE-HostPrepDescendantAcl.ps1"
        ExpectedTierSupport = @("host-preparation")
        Prerequisites = @("wxc-host-prep", "administrator", "disposable NTFS volume")
        HarnessArguments = "HostPrep"
        Destructive = $true
    }
    "694" = @{
        FriendlyName = "DOS Path Resolution"
        Script = "test_cases\Invoke-Issue694-GetFinalPathNameByHandle.ps1"
        ExpectedTierSupport = @("appcontainer-dacl")
        Prerequisites = @("force-tier-testing wxc-exec", "MXC_FORCE_TIER=appcontainer-dacl", "Go")
        Dependencies = @(
            @{
                Name = "Go"
                Executable = "go.exe"
                WingetId = "GoLang.Go"
                ArgumentName = "GoExe"
            }
        )
        HarnessArguments = "Default"
        Destructive = $false
    }
    "785" = @{
        FriendlyName = "Capture Probe Agreement"
        Script = "test_cases\Invoke-Issue785-ProbeCaptureDenials.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-sbox")
        Prerequisites = @("wxc-exec", "captureDenials support")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "825" = @{
        FriendlyName = "PowerShell Provider Location"
        Script = "test_cases\Invoke-Issue825-PowerShellProviderLocation.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec", "secondary NTFS volume", "PowerShell")
        HarnessArguments = "SecondaryDrive"
        Destructive = $false
    }
    "902" = @{
        FriendlyName = "Relative Working Directory"
        Script = "test_cases\Invoke-Issue902-RelativeWorkingDirectory.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "1061" = @{
        FriendlyName = "MSYS Object Namespace"
        Script = "test_cases\Invoke-Issue1061-MsysBaseNamedObjects.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec", "Git Bash or MSYS2")
        Dependencies = @(
            @{
                Name = "Git for Windows"
                Executable = "bash.exe"
                Paths = @("%ProgramFiles%\Git\bin\bash.exe")
                WingetId = "Git.Git"
                ArgumentName = "BashExe"
            }
        )
        HarnessArguments = "Default"
        Destructive = $false
    }
    "1102" = @{
        FriendlyName = "Default PATH Inheritance"
        Script = "test_cases\Invoke-Issue1102-DefaultPath.ps1"
        ExpectedTierSupport = @("appcontainer-bfs", "appcontainer-dacl", "base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "1109" = @{
        FriendlyName = "Volume Root Grant"
        Script = "test_cases\Invoke-Issue1109-BaseContainerVolumeRoot.ps1"
        ExpectedTierSupport = @("base-container-psec", "base-container-sbox")
        Prerequisites = @("wxc-exec", "BaseContainer-capable host")
        HarnessArguments = "Default"
        Destructive = $false
    }
    "1130" = @{
        FriendlyName = "SBOX Environment Fallback"
        Script = "test_cases\Invoke-Issue1130-SboxSparseEnvironment.ps1"
        ExpectedTierSupport = @("base-container-sbox")
        Prerequisites = @("wxc-exec", "SBOX-capable host")
        HarnessArguments = "Default"
        Destructive = $false
    }
}
