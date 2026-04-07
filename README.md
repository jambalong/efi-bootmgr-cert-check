# Invoke-BootMgrCertCheck

Checks whether the EFI boot manager binary on a Windows 11 endpoint is signed by the **Windows UEFI CA 2023** certificate. Designed for fleet deployment via ManageEngine Endpoint Central.

## Background

A machine may have the 2023 Secure Boot certificates written to its DB store but still be running a boot manager signed by the 2011 chain, this happens when the certificate update was deployed but the machine hasn't completed the subsequent reboot required to replace the binary. Checking the Secure Boot DB alone doesn't confirm compliance. The only definitive check is reading the signing certificate from `bootmgfw.efi` on the EFI partition itself.

`Get-AuthenticodeSignature` and `Get-PfxCertificate` both return incorrect issuer data for EFI binaries due to a [known PowerShell issue](https://github.com/PowerShell/PowerShell/issues/23820). This script uses `X509Certificate.CreateFromSignedFile` instead.

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 minimum (64-bit process required) |
| Privileges | Must run as Administrator |
| Execution policy | RemoteSigned or Unrestricted |
| Platform | Windows 11 physical endpoints only |
| VMs | Out of scope, UEFI firmware variable access is inconsistent in virtual environments |

## Usage

```powershell
.\Invoke-BootMgrCertCheck.ps1 -OutputPath \\server\securebootcheck
```

`-OutputPath` is mandatory and must be a UNC path. The output directory is created automatically if it does not exist.

## Output

Each machine writes one CSV file to the output path:

```
COMPUTERNAME_yyyyMMdd_HHmmss_UTC.csv
```

| Column | Type | Description |
|---|---|---|
| ComputerName | String | Machine hostname |
| Timestamp | ISO 8601 | UTC timestamp of execution |
| Status | Enum | See status values below |
| BootMgr_IsSigned2023 | Boolean / blank | True if bootmgfw.efi is signed by Windows UEFI CA 2023 |
| BootMgr_Issuer | String / blank | Full Issuer field of the signing certificate |
| Error | String / blank | Failure message if applicable |

### Status values

| Status | Meaning |
|---|---|
| `COMPLIANT` | bootmgfw.efi is signed by Windows UEFI CA 2023 |
| `NON_COMPLIANT` | bootmgfw.efi was read but is not signed by Windows UEFI CA 2023. Actual issuer recorded in BootMgr_Issuer |
| `SECURE_BOOT_DISABLED` | Secure Boot is present but not enforcing. Boot manager binary was not checked |
| `NOT_APPLICABLE` | Machine does not support UEFI firmware variables (legacy BIOS or VM) |
| `ERROR` | Unexpected failure. Error column contains the specific message |

## Aggregating results

After all endpoints have reported, combine the per-machine CSVs from a machine with access to the share:

```powershell
$csvFiles = Get-ChildItem '\\server\securebootaudit' -Filter '*_UTC.csv'
$combined = $csvFiles | ForEach-Object { Import-Csv $_.FullName }
$combined | Export-Csv '\\server\securebootaudit\SecureBootCert_Audit.csv' -NoTypeInformation -Encoding UTF8
```

When reviewing the combined report, prioritize: **NON_COMPLIANT** (requires remediation) → **SECURE_BOOT_DISABLED** → **ERROR** → **NOT_APPLICABLE** → **COMPLIANT**.

## Deployment notes

- Deploy as a Script task in ManageEngine Endpoint Central targeting Windows 11 physical endpoints
- Pass the UNC output path as the `-OutputPath` argument
- Ensure the task runs under a 64-bit PowerShell process (`Confirm-SecureBootUEFI` requires 64-bit)
- The executing account needs Administrator privileges on the endpoint and write access to the UNC share
- The script mounts and unmounts the EFI partition as its only side effect; the partition is always unmounted in a `finally` block regardless of outcome

## Known limitations

- **Issuer matching:** If Microsoft introduces an intermediate CA in a future update, the compliance check may return `NON_COMPLIANT` rather than an error. Acceptable for the current certificate structure.
- **Firmware variable removal:** Some firmware removes Secure Boot variables entirely when disabled rather than setting them to false, causing `Confirm-SecureBootUEFI` to throw a `GetFWVarFailed` exception. This surfaces as `ERROR` rather than `SECURE_BOOT_DISABLED`. Out of scope for the target environment (Windows 11 Dell endpoints).
- **Binary scope:** Only checks `bootmgfw.efi` on the EFI partition. Does not check the staged binary at `C:\Windows\Boot\EFI_EX\bootmgfw_EX.efi`.

## Related

| Resource | Details |
|---|---|
| KB5062713 / KB5062710 / KB5025885 / KB5016061 | Microsoft KBs for the 2023 Secure Boot certificate update. KB presence does not guarantee certificate deployment |
| Windows UEFI CA 2023 thumbprint | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` (SHA-1) |
| [PowerShell issue #23820](https://github.com/PowerShell/PowerShell/issues/23820) | Documents why `Get-AuthenticodeSignature` returns incorrect results for EFI binaries |
