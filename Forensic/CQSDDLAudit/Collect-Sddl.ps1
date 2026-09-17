<#
.SYNOPSIS
    Collects security descriptors in SDDL form for CQSDDLAudit.py.

.DESCRIPTION
    Services are the primary surface and the default.

    Enumeration goes through the registry, not the Service Control Manager. That
    is the whole point: a service can deny SERVICE_QUERY_STATUS (LC) to
    Interactive, Service and Administrators, which removes it from `sc query`,
    services.msc and Get-Service, while it keeps running. Every service is
    registered under HKLM\SYSTEM\CurrentControlSet\Services regardless, and its
    descriptor sits in the Security value of that key, so reading the registry
    sees what the SCM will not show you.

    Each row records whether SCM enumeration returned the service. The
    difference between the registry list and the SCM list is itself a finding,
    and CQSDDLAudit reports it as one.

    Run elevated. Without SeSecurityPrivilege and administrative read on the
    Services hive, many Security values are unreadable and the collection is
    incomplete. The script says so rather than producing a quiet, short list.

.PARAMETER OutFile
    CSV to write. Defaults to services-sddl.csv beside this script.

.PARAMETER Path
    Also collect file and directory descriptors from these paths.

.PARAMETER RegistryKey
    Also collect registry key descriptors, e.g. HKLM:\SOFTWARE\Microsoft.

.PARAMETER Recurse
    Recurse into -Path and -RegistryKey.

.PARAMETER Depth
    Recursion depth for -Recurse. Default 2, because permission sweeps get large
    fast and an unbounded walk of C:\ is rarely what anyone meant.

.PARAMETER SkipServices
    Do not collect services. Only useful with -Path or -RegistryKey.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Collect-Sddl.ps1 -OutFile services.csv

.EXAMPLE
    .\Collect-Sddl.ps1 -Path 'C:\Program Files' -RegistryKey 'HKLM:\SOFTWARE' -Recurse

.NOTES
    Author: Paula Januszkiewicz | CQURE
    License: Apache License 2.0
#>
[CmdletBinding()]
param(
    [string]   $OutFile      = (Join-Path $PSScriptRoot 'services-sddl.csv'),
    [string[]] $Path         = @(),
    [string[]] $RegistryKey  = @(),
    [switch]   $Recurse,
    [int]      $Depth        = 2,
    [switch]   $SkipServices
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-SddlFromBytes {
    <#  A REG_BINARY Security value is a self-relative SECURITY_DESCRIPTOR.
        RawSecurityDescriptor parses it without touching the SCM, so this works
        for services the SCM will not talk to us about. #>
    param([byte[]] $Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 20) { return $null }
    try {
        $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Bytes, 0)
        return $rsd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    } catch {
        return $null
    }
}

$rows = New-Object System.Collections.Generic.List[object]

# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------
if (-not $SkipServices) {

    if (-not (Test-Elevated)) {
        Write-Warning ("Not elevated. Many Security values under the Services hive will be " +
                       "unreadable, so this collection will be incomplete. Re-run as administrator.")
    }

    # What the SCM is willing to admit exists. Anything in the registry but not
    # in here is the interesting case.
    $enumerated = @{}
    try {
        foreach ($s in Get-Service -ErrorAction SilentlyContinue) {
            $enumerated[$s.Name.ToLowerInvariant()] = $true
        }
    } catch {
        Write-Warning "Get-Service failed, every service will be reported as not enumerated: $_"
    }

    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $keys = Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue
    Write-Host ("Registry lists {0} service keys, SCM enumeration returned {1}." -f `
                $keys.Count, $enumerated.Count)

    $unreadable = 0
    foreach ($key in $keys) {
        $name = $key.PSChildName
        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { }

        $type      = if ($props -and $props.PSObject.Properties['Type'])        { [int]$props.Type }      else { 0 }
        $start     = if ($props -and $props.PSObject.Properties['Start'])       { [int]$props.Start }     else { -1 }
        $imagePath = if ($props -and $props.PSObject.Properties['ImagePath'])   { [string]$props.ImagePath } else { '' }
        $account   = if ($props -and $props.PSObject.Properties['ObjectName'])  { [string]$props.ObjectName } else { '' }
        $display   = if ($props -and $props.PSObject.Properties['DisplayName']) { [string]$props.DisplayName } else { '' }

        # Only Win32 services are returned by SCM enumeration under their own
        # name. Two other categories are not, and calling either one hidden is a
        # false positive on every machine:
        #   drivers (no 0x10/0x20 bit)
        #   per-user service templates (0x40 set, 0x80 clear), e.g. OneSyncSvc.
        #     The SCM enumerates their per-user instances, OneSyncSvc_4a1f2,
        #     never the template, so the template is absent by design.
        $isUserTemplate = (($type -band 0x40) -ne 0) -and (($type -band 0x80) -eq 0)
        $isWin32 = ((($type -band 0x10) -ne 0) -or (($type -band 0x20) -ne 0)) -and (-not $isUserTemplate)

        $sddl     = $null
        $sdSource = ''
        $note     = ''

        $secKey = Join-Path $key.PSPath 'Security'
        try {
            $sec = Get-ItemProperty -LiteralPath $secKey -Name 'Security' -ErrorAction Stop
            $sddl = ConvertTo-SddlFromBytes -Bytes $sec.Security
            if ($sddl) { $sdSource = 'registry' } else { $note = 'Security value present but not parseable' }
        } catch [System.Management.Automation.ItemNotFoundException] {
            $note = 'no Security value, the service uses the SCM default descriptor'
        } catch {
            $unreadable++
            $note = 'Security value unreadable: ' + $_.Exception.Message
        }

        # Cross-check with the SCM. Where sdshow disagrees or refuses, that is
        # itself worth recording.
        $sdShow = ''
        if ($isWin32) {
            try {
                $out = & sc.exe sdshow $name 2>$null
                $line = $out | Where-Object { $_ -match '^\s*[ODGS]:' } | Select-Object -First 1
                if ($line) { $sdShow = $line.Trim() }
            } catch { }
        }
        if (-not $sddl -and $sdShow) {
            $sddl = $sdShow
            $sdSource = 'sc sdshow'
        }
        if (-not $sddl) { continue }   # nothing to analyse for this key

        $enumVisible = 'False'
        if ($isUserTemplate) {
            $enumVisible = 'n/a (per-user template)'
        } elseif (-not $isWin32) {
            $enumVisible = 'n/a (driver)'
        } elseif ($enumerated.ContainsKey($name.ToLowerInvariant())) {
            $enumVisible = 'True'
        }

        if ($sdSource -eq 'registry' -and $isWin32 -and -not $sdShow) {
            $extra = 'sc sdshow returned nothing while the registry descriptor was readable'
            $bits = @($note, $extra) | Where-Object { $_ }
            $note = ($bits -join '; ')
        }

        $rows.Add([pscustomobject]@{
            Source      = $name
            ObjectType  = 'service'
            Sddl        = $sddl
            DisplayName = $display
            Account     = $account
            StartMode   = switch ($start) { 0 {'Boot'} 1 {'System'} 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} default {''} }
            ServiceType = ('0x{0:X}' -f $type)
            ImagePath   = $imagePath
            EnumVisible = $enumVisible
            SdSource    = $sdSource
            Notes       = $note
        })
    }

    if ($unreadable -gt 0) {
        Write-Warning ("{0} Security value(s) could not be read. Re-run elevated for a complete picture." -f $unreadable)
    }
}

# --------------------------------------------------------------------------
# Files and directories
# --------------------------------------------------------------------------
foreach ($p in $Path) {
    $items = @()
    try {
        $items += Get-Item -LiteralPath $p -Force -ErrorAction Stop
        if ($Recurse) {
            $items += Get-ChildItem -LiteralPath $p -Recurse -Depth $Depth -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "skipped ${p}: $_"
        continue
    }
    foreach ($item in $items) {
        try {
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $rows.Add([pscustomobject]@{
                Source      = $item.FullName
                ObjectType  = if ($item.PSIsContainer) { 'directory' } else { 'file' }
                Sddl        = $acl.Sddl
                DisplayName = ''
                Account     = $acl.Owner
                StartMode   = ''
                ServiceType = ''
                ImagePath   = ''
                EnumVisible = ''
                SdSource    = 'Get-Acl'
                Notes       = 'Get-Acl reorders ACEs; treat order findings from this source with care'
            })
        } catch {
            Write-Warning ("skipped {0}: {1}" -f $item.FullName, $_.Exception.Message)
        }
    }
}

# --------------------------------------------------------------------------
# Registry keys
# --------------------------------------------------------------------------
foreach ($k in $RegistryKey) {
    $items = @()
    try {
        $items += Get-Item -LiteralPath $k -ErrorAction Stop
        if ($Recurse) {
            $items += Get-ChildItem -LiteralPath $k -Recurse -Depth $Depth -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "skipped ${k}: $_"
        continue
    }
    foreach ($item in $items) {
        try {
            $acl = Get-Acl -LiteralPath $item.PSPath -ErrorAction Stop
            $rows.Add([pscustomobject]@{
                Source      = $item.Name
                ObjectType  = 'registry'
                Sddl        = $acl.Sddl
                DisplayName = ''
                Account     = $acl.Owner
                StartMode   = ''
                ServiceType = ''
                ImagePath   = ''
                EnumVisible = ''
                SdSource    = 'Get-Acl'
                Notes       = ''
            })
        } catch {
            Write-Warning ("skipped {0}: {1}" -f $item.Name, $_.Exception.Message)
        }
    }
}

# --------------------------------------------------------------------------
if ($rows.Count -eq 0) {
    Write-Warning 'Nothing collected.'
    exit 1
}

$rows | Export-Csv -LiteralPath $OutFile -NoTypeInformation -Encoding UTF8
Write-Host ("Wrote {0} ({1} descriptor(s))." -f $OutFile, $rows.Count)

$svc = @($rows | Where-Object { $_.ObjectType -eq 'service' })
$notEnum = @($svc | Where-Object { $_.EnumVisible -eq 'False' })
if ($notEnum.Count -gt 0) {
    Write-Host ''
    Write-Host ("{0} service(s) exist in the registry but were not returned by SCM enumeration:" -f $notEnum.Count) -ForegroundColor Yellow
    $notEnum | ForEach-Object { Write-Host ("  " + $_.Source) -ForegroundColor Yellow }
}
Write-Host ''
Write-Host ("Next:  py -3 CQSDDLAudit.py services --input {0} --html report.html" -f $OutFile)
