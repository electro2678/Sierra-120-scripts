 === Start Transcript ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "$env:USERPROFILE\Desktop\System_Audit_$timestamp.txt"
Start-Transcript -Path $logPath -Append

# Set hostname to $PC
$PC = $env:COMPUTERNAME

# --- CPU Info ---
Write-Output "`n--- CPU Info ---`n"

$cpuProps = @(
    @{Label = "CPU"; Expression = { $_.Name }},
    @{Label = "Manufacturer"; Expression = { $_.Manufacturer }},
    @{Label = "Current Speed (GHz)"; Expression = { [math]::Round($_.CurrentClockSpeed / 1000, 2) }},
    @{Label = "Max Speed (GHz)"; Expression = { [math]::Round($_.MaxClockSpeed / 1000, 2) }},
    @{Label = "Caption"; Expression = { $_.Caption }},
    @{Label = "Architecture"; Expression = { $_.Architecture }},
    @{Label = "Cores"; Expression = { $_.NumberOfCores }},
    @{Label = "Logical Processors"; Expression = { $_.NumberOfLogicalProcessors }},
    @{Label = "Address Width"; Expression = { $_.AddressWidth }},
    @{Label = "Data Width"; Expression = { $_.DataWidth }}
)

Get-WmiObject Win32_Processor -ComputerName $PC | Format-List $cpuProps

# --- Windows System Info ---
Write-Output "`n--- Windows System Info ---`n"

$OS = Get-WmiObject Win32_OperatingSystem -ComputerName $PC

Write-Output "`n`tOperating System"
Write-Output "OS: $($OS.Caption) $($OS.CSDVersion)  Build: $($OS.BuildNumber) $($OS.BuildType) $($OS.OSArchitecture)"
Write-Output "Free Physical Memory: $([Math]::Round($OS.FreePhysicalMemory / 1MB, 3)) MB ($($OS.FreePhysicalMemory) KB)"
Write-Output "Free Space In Paging Files: $([Math]::Round($OS.FreeSpaceInPagingFiles / 1MB, 3)) MB ($($OS.FreeSpaceInPagingFiles) KB)"

$uptime = (Get-Date) - ([Management.ManagementDateTimeConverter]::ToDateTime($OS.LastBootUpTime))
Write-Output ("Uptime: {0:00} Days {1:00} Hrs {2:00} Min" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)

# --- RAM Info ---
Write-Output "`n--- RAM Info ---`n"

Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object `
    @{Name = 'Total RAM (GB)'; Expression = { [math]::Round($_.TotalVisibleMemorySize / 1MB, 2) }},
    @{Name = 'Free RAM (GB)'; Expression = { [math]::Round($_.FreePhysicalMemory / 1MB, 2) }},
    @{Name = 'Used RAM (GB)'; Expression = { [math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / 1MB, 2) }} |
    Out-String | Write-Output

# --- Disk Info ---
Write-Output "`n--- Disk Info ---`n"
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Select-Object `
    DeviceID,
    @{Name = "Total(GB)"; Expression = { [math]::Round($_.Size / 1GB, 2) }},
    @{Name = "Free(GB)"; Expression  = { [math]::Round($_.FreeSpace / 1GB, 2) }},
    @{Name = "Used(GB)"; Expression  = { [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2) }},
    @{Name = "Free(%)"; Expression  = { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) }}

# --- Installed Applications ---
Write-Output "`n--- Installed Applications ---`n"

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$apps = foreach ($path in $registryPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -and $_.DisplayVersion
    } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}

$apps | Sort-Object DisplayName | Format-Table -AutoSize | Out-String | Write-Output

# --- Network Information ---
Write-Output "`n--- Network Information ---`n"

Write-Output "`n--- Full Network Adapter & IP Information ---`n"

# Get physical adapters
$adapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }

foreach ($adapter in $adapters) {
    $name = $adapter.Name
    $status = switch ($adapter.NetConnectionStatus) {
        0 { 'Disconnected' }
        1 { 'Connecting' }
        2 { 'Connected' }
        3 { 'Disconnecting' }
        4 { 'Hardware not present' }
        5 { 'Hardware disabled' }
        6 { 'Hardware malfunction' }
        7 { 'Media disconnected' }
        8 { 'Authenticating' }
        9 { 'Authentication succeeded' }
        10 { 'Authentication failed' }
        11 { 'Invalid Address' }
        12 { 'Credentials required' }
        default { 'Unknown' }
    }

    Write-Output "Adapter Name    : $($adapter.Name)"
    Write-Output "MAC Address     : $($adapter.MACAddress)"
    Write-Output "Speed (bps)     : $($adapter.Speed)"
    Write-Output "Adapter Type    : $($adapter.AdapterType)"
    Write-Output "Manufacturer    : $($adapter.Manufacturer)"
    Write-Output "Status          : $status"
    Write-Output "NetConnectionID : $($adapter.NetConnectionID)"
    Write-Output ""

    # Get matching IP configuration using InterfaceAlias or NetConnectionID
    $ipInfo = Get-NetIPConfiguration | Where-Object { $_.InterfaceAlias -eq $adapter.NetConnectionID }

    if ($ipInfo) {
        foreach ($ip in $ipInfo.IPv4Address) {
            Write-Output "IPv4 Address    : $($ip.IPAddress)"
        }

        if ($ipInfo.IPv6Address) {
            foreach ($ipv6 in $ipInfo.IPv6Address) {
                Write-Output "IPv6 Address    : $($ipv6.IPAddress)"
            }
        }

        Write-Output "Default Gateway : $($ipInfo.IPv4DefaultGateway.NextHop)"
        Write-Output "DNS Servers     : $($ipInfo.DnsServer.ServerAddresses -join ', ')"
    } else {
        Write-Output "No IP Configuration found for this adapter."
    }

    Write-Output "`n------------------------------------------------------------`n"
}

# --- IIS Application Pools ---
Write-Output "`n--- IIS Application Pools ---`n"

if (Get-Module -ListAvailable -Name WebAdministration) {
    try {
        Import-Module WebAdministration
        Get-ChildItem IIS:\AppPools | Select-Object Name,
            @{Name="IdentityType";Expression={ $_.processModel.identityType }},
            @{Name="UserName";Expression={ $_.processModel.userName }} |
            Out-String | Write-Output
    } catch {
        Write-Warning "Failed to retrieve IIS App Pools."
    }
} else {
    Write-Warning "WebAdministration module not found. Skipping IIS info."
}

# --- Scheduled Tasks ---
Write-Output "`n--- Scheduled Tasks ---`n"

try {
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
        [PSCustomObject]@{
            TaskName  = $task.TaskName
            Path      = $task.TaskPath
            RunAsUser = $task.Principal.UserId
            State     = $info.State
        }
    } | Where-Object {
        $_.RunAsUser -and $_.RunAsUser -notmatch "^(NT AUTHORITY|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$"
    } | Out-String | Write-Output
} catch {
    Write-Warning "Failed to retrieve scheduled tasks."
}

# --- Local Users with Group Memberships (WMI version, works on all systems) ---
Write-Output "`n--- Local Users with Group Memberships (WMI) ---`n"

$localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

foreach ($user in $localUsers) {
    Write-Output "Username   : $($user.Name)"
    Write-Output "Domain     : $($user.Domain)"
    Write-Output "Disabled   : $($user.Disabled)"
    Write-Output "Lockout    : $($user.Lockout)"
    Write-Output "SID        : $($user.SID)"

    try {
        $userObj = [ADSI]"WinNT://$($user.Domain)/$($user.Name),user"
        $groups = $userObj.Groups() | ForEach-Object {
            $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }
        $groupList = if ($groups) { $groups -join ', ' } else { "None" }
    } catch {
        $groupList = "Unknown or access denied"
    }

    Write-Output "Groups     : $groupList"
    Write-Output "-----------------------------`n"
}

# --- Domain Users (if module available) ---
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        Import-Module ActiveDirectory
        Write-Output "`n--- Domain Users (Top 100) with Group Memberships ---`n"

        $domainUsers = Get-ADUser -Filter * -Property DisplayName, Enabled | Select-Object -First 100

        foreach ($user in $domainUsers) {
            Write-Output "SAM Account Name : $($user.SamAccountName)"
            Write-Output "Display Name     : $($user.DisplayName)"
            Write-Output "Enabled          : $($user.Enabled)"

            try {
                $groups = Get-ADUser $user.SamAccountName -Properties MemberOf |
                          Select-Object -ExpandProperty MemberOf

                if ($groups) {
                    $groupNames = $groups | ForEach-Object {
                        ($_ -split ',')[0] -replace '^CN='
                    } | Sort-Object | Select-Object -First 5  # Show up to 5 groups
                    Write-Output "Groups           : $($groupNames -join ', ')"
                } else {
                    Write-Output "Groups           : None"
                }
            } catch {
                Write-Output "Groups           : Unknown or access denied"
            }

            Write-Output "-----------------------------`n"
        }
    } catch {
        Write-Warning "Error querying domain users."
    }
} else {
    Write-Warning "Active Directory module not found. Cannot list domain users."
}
# === End Transcript ===
Stop-Transcript
Write-Output "`nSystem audit saved to: $logPath"
