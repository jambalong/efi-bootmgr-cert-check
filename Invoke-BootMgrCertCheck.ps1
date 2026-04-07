#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks whether the EFI partition boot manager is signed by Windows UEFI CA 2023.

.DESCRIPTION
    Mounts the EFI system partition, reads the boot manager binary signature using
    X509Certificate.CreateFromSignedFile, and writes a single CSV row to the output path.

    This is a lean signal-only check. If a machine is non-compliant, further diagnostic
    investigation will be needed to determine root cause.

.PARAMETER OutputPath
    Directory where the per-machine CSV result will be written.
    UNC path is mandatory for production deployment.

.EXAMPLE
    .\Invoke-BootMgrCertCheck.ps1 -OutputPath \\server\securebootcheck

.NOTES
    Requirements:
        Must run as Administrator
        Must run under 64-bit PowerShell (Confirm-SecureBootUEFI requires 64-bit)
        Execution policy must be RemoteSigned or Unrestricted

    Assumed Environment:
        Windows 11 physical endpoints only
        VMs are out of scope because UEFI firmware variable access is inconsistent

    Date: 03-2026
    Author: John-Alvin Ambalong
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}


# -------------------------------------------------------------------
# CONSTANTS
# -------------------------------------------------------------------

$CERT_WIN_UEFI_2023 = 'Windows UEFI CA 2023'
$EFI_PARTITION_PATH = '\EFI\Microsoft\Boot\bootmgfw.efi'


# -------------------------------------------------------------------
# UEFI AND SECURE BOOT CHECK
# -------------------------------------------------------------------

function Test-SecureBootState {
    [CmdletBinding()]
    param()

    try {
        $isEnabled = Confirm-SecureBootUEFI
        return [PSCustomObject]@{
            IsUefi = $true
            IsEnabled = $isEnabled
        }
    }
    catch {
        if ($_.Exception.Message -match 'Cmdlet not supported on this platform') {
            return [PSCustomObject]@{ IsUefi = $false; IsEnabled = $false }
        }
        # Note: some firmware removes Secure Boot variables entirely when disabled,
        # which throws a StatusException (GetFWVarFailed) not caught here.
        # This is not handled and out of scope for this deployment environment.
        throw
    }
}


# -------------------------------------------------------------------
# BOOT MANAGER SIGNATURE CHECK
# -------------------------------------------------------------------
# Mounts the EFI system partition and reads the signing certificate from
# the boot manager binary using X509Certificate.CreateFromSignedFile.
#
# Get-AuthenticodeSignature and Get-PfxCertificate are not used.
# Both return incorrect results for EFI binaries.
# See: https://github.com/PowerShell/PowerShell/issues/23820

function Get-BootManagerSignature {
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        IsSigned2023 = $false
        Issuer = ''
        Error = ''
    }

    $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
    $availableLetter = 'S','T','U','V','W','X','Y','Z' | Where-Object { $usedLetters -notcontains $_ } | Select-Object -First 1

    if (-not $availableLetter) {
        $result.Error = 'No available drive letter for EFI partition mount'
        return $result
    }

    $efiPath = "$availableLetter`:$EFI_PARTITION_PATH"
    $mounted = $false

    try {
        $null = mountvol "$availableLetter`:" /s

        if (-not (Test-Path "$availableLetter`:")) {
            $result.Error = "EFI partition mount failed"
            return $result
        }

        $mounted = $true

        if (-not (Test-Path $efiPath)) {
            $result.Error = "Boot manager not found at $efiPath"
            return $result
        }

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($efiPath)
        $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)

        $result.Issuer = $cert2.Issuer

        # Matches the Issuer field of the signing cert. If Microsoft adds an intermediate CA, this may silently return NON_COMPLIANT.
        $result.IsSigned2023 = $cert2.Issuer -match [regex]::Escape($CERT_WIN_UEFI_2023)
    }
    catch {
        $result.Error = "EFI partition check failed: $($_.Exception.Message)"
    }
    finally {
        # Always unmount regardless of outcome.
        if ($mounted) {
            $null = mountvol "$availableLetter`:" /d
            $unmountExitCode = $LASTEXITCODE

            if ($unmountExitCode -ne 0) {
                $unmountError = "EFI partition unmount failed at ${availableLetter}: (exit code $unmountExitCode)"
                $result.Error = if ($result.Error) { "$($result.Error); $unmountError" } else { $unmountError }
            }
        }
    }

    return $result
}


# -------------------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------------------

$now = (Get-Date).ToUniversalTime()
$timestamp = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
$utcStamp = $now.ToString('yyyyMMdd_HHmmss')
$status = 'ERROR'
$issuer = ''
$errorValue = ''
$bmSig = $null

try {
    $secureBootState = Test-SecureBootState
}
catch {
    $secureBootState = $null
    $errorValue = "Secure Boot state check failed: $($_.Exception.Message)"
}

if ($secureBootState) {
    if (-not $secureBootState.IsUefi) {
        $status = 'NOT_APPLICABLE'
        $errorValue = 'UEFI firmware variables not accessible'
    }
    elseif (-not $secureBootState.IsEnabled) {
        $status = 'SECURE_BOOT_DISABLED'
    }
    else {
        $bmSig = Get-BootManagerSignature

        if ($bmSig.Error) {
            $status = 'ERROR'
            $errorValue = $bmSig.Error
        }
        else {
            $status = if ($bmSig.IsSigned2023) { 'COMPLIANT' } else { 'NON_COMPLIANT' }
            $issuer = $bmSig.Issuer
        }
    }
}

$record = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = $timestamp
    Status = $status
    BootMgr_IsSigned2023 = if ($bmSig -and -not $bmSig.Error) { $bmSig.IsSigned2023 } else { '' }
    BootMgr_Issuer = $issuer
    Error = $errorValue
}


# -------------------------------------------------------------------
# CSV EXPORT
# -------------------------------------------------------------------

if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    catch {
        if (-not (Test-Path $OutputPath)) {
            Write-Warning "Could not create output path '$OutputPath': $($_.Exception.Message)"
            exit 1
        }
    }
}

$csvFile = Join-Path $OutputPath "$($env:COMPUTERNAME)_$utcStamp`_UTC.csv"

try {
    $record | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Warning "Could not write CSV to '$csvFile': $($_.Exception.Message)"
    exit 1
}

# -------------------------------------------------------------------
# AGGREGATION (run separately after all endpoints have been assessed)
# -------------------------------------------------------------------
# To combine all per-machine CSVs into a single report, run the following
# from the machine that has access to the shared UNC path:
#
# $csvFiles = Get-ChildItem '\\server\\securebootaudit\' -Filter '*_UTC.csv'
# $combined = $csvFiles | ForEach-Object { Import-Csv $_.FullName }
# $combined | Export-Csv '\\server\\securebootaudit\SecureBootCert_Audit.csv' -NoTypeInformation -Encoding UTF8
#
# Replace \\server\\securebootaudit\ with your actual UNC path.
