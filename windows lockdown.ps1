function Set-NetAccountPolicy {
    param (
        [string]$Description,
        [string]$Command,
        [string]$VerifyMatch
    )
    try {
        Write-Host "`n$Description..." -ForegroundColor Cyan
        Invoke-Expression $Command
        Start-Sleep -Seconds 1
        net accounts | Select-String $VerifyMatch
        Write-Host "$Description successfully applied." -ForegroundColor Green
    } catch {
        Write-Host "Failed to apply: $Description. Error: $_" -ForegroundColor Red
    }
}

function Set-AuditPolicy {
    param (
        [string]$Subcategory,
        [string]$Success = "enable",
        [string]$Failure = $null
    )
    try {
        Write-Host "`nConfiguring audit policy: $Subcategory..." -ForegroundColor Cyan
        $cmd = "AuditPol /set /subcategory:`"$Subcategory`" /success:$Success"
        if ($Failure) {
            $cmd += " /failure:$Failure"
        }
        Invoke-Expression $cmd
        Start-Sleep -Seconds 1
        AuditPol /get /subcategory:"$Subcategory"
        Write-Host "Audit policy '$Subcategory' successfully set." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set audit policy '$Subcategory'. Error: $_" -ForegroundColor Red
    }
}

# --- Password Policy ---
Set-NetAccountPolicy "Setting password history to 24 passwords" 'net accounts /uniquepw:24' "Password history length"
Set-NetAccountPolicy "Setting maximum password age to 60 days" 'net accounts /maxpwage:60' "Maximum password age"
Set-NetAccountPolicy "Setting minimum password age to 1 day" 'net accounts /minpwage:1' "Minimum password age"
Set-NetAccountPolicy "Setting minimum password length to 14 characters" 'net accounts /minpwlen:14' "Minimum password length"

# --- Audit Policies ---
Set-AuditPolicy "Credential Validation" "enable" "enable"
Set-AuditPolicy "Kerberos Authentication Service" "enable" "enable"
Set-AuditPolicy "Kerberos Service Ticket Operations" "enable" "enable"
Set-AuditPolicy "Application Group Management" "enable" "enable"
Set-AuditPolicy "Computer Account Management" "enable"
Set-AuditPolicy "User Account Management" "enable" "enable"

# --- Account Lockout Policies ---
Set-NetAccountPolicy "Setting account lockout duration to 15 minutes" 'net accounts /lockoutduration:15' "Lockout duration"
Set-NetAccountPolicy "Setting account lockout threshold to 5 attempts" 'net accounts /lockoutthreshold:5' "Lockout threshold"
Set-NetAccountPolicy "Setting reset account lockout counter after 15 minutes" 'net accounts /lockoutwindow:15' "Lockout observation window"

