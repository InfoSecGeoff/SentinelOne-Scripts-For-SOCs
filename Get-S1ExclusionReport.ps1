<#
.SYNOPSIS
    Retrieves all SentinelOne exclusions and generates a comprehensive report.

.DESCRIPTION
    Queries the SentinelOne API to retrieve all exclusions configured in the environment.
    Results are organized by Account and Site with detailed information about each exclusion.
    Supports filtering by client/site name, date ranges, and various exclusion types.

.PARAMETER BaseUrl
    SentinelOne console URL

.PARAMETER ApiToken
    SentinelOne API token for authentication

.PARAMETER ExportFormat
    Export format: "Console", "CSV", "JSON", "HTML", "All" (Default: "Console")

.PARAMETER OutputPath
    Directory path for exported files

.PARAMETER IncludeSystemExclusions
    Include system-generated exclusions

.PARAMETER GroupBySite
    Group results by Site instead of Account

.PARAMETER FilterSource
    Filter by source of "user", "cloud", or "catalog"

.PARAMETER FilterThreatType
    Filter by threat type of "EDR" or "Threat"

.PARAMETER ClientName
    Filter by client/account name(s). Supports wildcards.

.PARAMETER SiteName
    Filter by site/group name(s). Supports wildcards.

.PARAMETER CreatedAfter
    Filter exclusions created after a specific date

.PARAMETER CreatedWithinDays
    Filter exclusions created within the last X days

.PARAMETER GlobalOnly
    Only retrieve global level exclusions

.PARAMETER MaxThreads
    Number of concurrent threads for parallel queries (1-20, default: 10)

.EXAMPLE
    .\Get-S1ExclusionsReport.ps1 -BaseUrl "https://usea1-swprd1.sentinelone.net" -ApiToken "12345789790asdfjklgdkjasdf..."
    
.EXAMPLE
    .\Get-S1ExclusionsReport.ps1 -BaseUrl "https://usea1-swprd1.sentinelone.net" -ApiToken "12345789790asdfjklgdkjasdf..." -ClientName "Acme*" -ExportFormat HTML

.EXAMPLE
    .\Get-S1ExclusionsReport.ps1 -BaseUrl "https://usea1-swprd1.sentinelone.net" -ApiToken "12345789790asdfjklgdkjasdf..." -CreatedWithinDays 7 -ExportFormat All

.NOTES
    Author: Geoff Tankersley
    Version: 2.0
    Requires: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('https://.*\.sentinelone\.net$')]
    [string]$BaseUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$ApiToken,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSystemExclusions,
    
    [Parameter(Mandatory = $false)]
    [switch]$GroupBySite,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("user", "cloud", "catalog", "")]
    [string]$FilterSource,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("EDR", "Threat", "")]
    [string]$FilterThreatType,
    
    [Parameter(Mandatory = $false)]
    [Alias("AccountName", "Customer", "Client")]
    [string[]]$ClientName,
    
    [Parameter(Mandatory = $false)]
    [Alias("Site", "Group")]
    [string[]]$SiteName,
    
    [Parameter(Mandatory = $false)]
    [datetime]$CreatedAfter,
    
    [Parameter(Mandatory = $false)]
    [int]$CreatedWithinDays,
    
    [Parameter(Mandatory = $false)]
    [switch]$GlobalOnly,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$MaxThreads = 10
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:allExclusions = @()
$script:siteLookup = @{}
$script:enrichedExclusions = @()

function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $colors = @{
        "Info"    = "White"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error"   = "Red"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Get-SafeValue {
    param(
        [Parameter(Mandatory = $true)]
        $Value,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = "N/A"
    )
    
    if ($null -eq $Value -or $Value -eq "" -or $Value -eq "null") {
        return $DefaultValue
    }
    return $Value
}

function Get-ExclusionTypeName {
    param([string]$Type)
    
    $typeMapping = @{
        "path"             = "Path Exclusion"
        "file_type"        = "File Type Exclusion"
        "hash"             = "Hash Exclusion"
        "certificate"      = "Certificate Exclusion"
        "browser"          = "Browser Exclusion"
        "white_hash"       = "White Hash"
        "interoperability" = "Interoperability"
    }
    
    if ($typeMapping.ContainsKey($Type.ToLower())) {
        return $typeMapping[$Type.ToLower()]
    }
    return $Type
}

function Get-ThreatTypeName {
    param([string]$Type)
    
    $mapping = @{
        "EDR"    = "Behavioral (EDR)"
        "Threat" = "Static AI (Threat)"
    }
    
    if ($mapping.ContainsKey($Type)) {
        return $mapping[$Type]
    }
    return $Type
}

function Initialize-Headers {
    param([string]$Token)
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "ApiToken $Token")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Accept", "*/*")
    $headers.Add("User-Agent", "PowerShell-S1-Report/2.0")
    
    return $headers
}

function Get-SiteLookupTable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )
    
    Write-LogMessage "Fetching site information from SentinelOne..." -Level "Info"
    
    $lookup = @{}
    $cursor = $null
    $pageCount = 0
    
    try {
        do {
            $pageCount++
            $queryParams = @("limit=1000")
            
            if ($cursor) {
                $queryParams += "cursor=$cursor"
            }
            
            $url = "$BaseUrl/web/api/v2.1/sites?$($queryParams -join '&')"
            $response = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers -TimeoutSec 60
            
            if ($response.data.sites) {
                foreach ($site in $response.data.sites) {
                    if ($site.id) {
                        $lookup[$site.id] = @{
                            Name        = Get-SafeValue $site.name "Unknown Site"
                            AccountName = Get-SafeValue $site.accountName "Unknown Account"
                            AccountId   = Get-SafeValue $site.accountId "N/A"
                        }
                    }
                }
                Write-LogMessage "Loaded $($response.data.sites.Count) sites from page $pageCount" -Level "Info"
            }
            
            $cursor = $response.pagination.nextCursor
            
        } while ($null -ne $cursor -and $cursor -ne "" -and $cursor -ne "null")
        
        Write-LogMessage "Site lookup table created with $($lookup.Count) entries" -Level "Success"
        return $lookup
        
    } catch {
        Write-LogMessage "Warning: Could not fetch site information: $($_.Exception.Message)" -Level "Warning"
        return @{}
    }
}

function Find-MatchingSites {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$SiteLookup,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Patterns
    )
    
    $matchedSites = @()
    
    foreach ($pattern in $Patterns) {
        Write-LogMessage "Searching for sites matching: $pattern" -Level "Info"
        
        $matches = $SiteLookup.GetEnumerator() | Where-Object {
            $siteName = $_.Value.Name
            $accountName = $_.Value.AccountName
            
            # Extract company name and delete parenthetical contents
            $companyName = $siteName
            if ($siteName -match '^(.+?)\s*\([^)]+\)$') {
                $companyName = $matches[1].Trim()
            }
            
            $siteName -like $pattern -or `
            $companyName -like $pattern -or `
            $accountName -like $pattern -or `
            $siteName -like "*$pattern*"
        }
        
        foreach ($match in $matches) {
            $matchedSites += @{
                Id          = $match.Key
                Name        = $match.Value.Name
                AccountName = $match.Value.AccountName
            }
        }
    }
    
    return $matchedSites
}

function Get-GlobalExclusions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string[]]$QueryParams
    )
    
    Write-LogMessage "`n=== Retrieving Global/Account-Level Exclusions ===" -Level "Info"
    
    $exclusions = @()
    $cursor = $null
    $pageCount = 0
    
    try {
        do {
            $pageCount++
            $params = $QueryParams + @("limit=1000", "skipCount=false")
            
            if ($cursor) {
                $params += "cursor=$cursor"
            }
            
            $url = "$BaseUrl/web/api/v2.1/unified-exclusions?$($params -join '&')"
            Write-LogMessage "Fetching page $pageCount..." -Level "Info"
            
            $response = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers -TimeoutSec 60
            
            if ($response.data -and $response.data.Count -gt 0) {
                # Filter for global/account level only (scopePath has <= 2 parts)
                $globalItems = $response.data | Where-Object {
                    $parts = $_.scopePath -split '\\'
                    $parts.Count -le 2
                }
                
                $exclusions += $globalItems
                Write-LogMessage "Retrieved $($globalItems.Count) global exclusions" -Level "Success"
            }
            
            $cursor = $response.pagination.nextCursor
            
        } while ($null -ne $cursor -and $cursor -ne "" -and $cursor -ne "null")
        
        Write-LogMessage "Total global exclusions retrieved: $($exclusions.Count)" -Level "Success"
        return $exclusions
        
    } catch {
        Write-LogMessage "Error retrieving global exclusions: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

function Get-SiteExclusions {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Sites,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $true)]
        [string[]]$QueryParams,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxThreads = 10
    )
    
    if ($Sites.Count -eq 0) {
        return @()
    }
    
    Write-LogMessage "`n=== Retrieving Site-Level Exclusions ===" -Level "Info"
    Write-LogMessage "Querying $($Sites.Count) sites with $MaxThreads concurrent threads..." -Level "Info"
    
    $exclusions = @()
    
    # Create runspace pool for parallel processing
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $runspaces = @()
    
    # Script block for parallel execution
    $scriptBlock = {
        param($SiteInfo, $BaseUrl, $Headers, $QueryParams)
        
        try {
            $params = $QueryParams + @("limit=1000", "skipCount=false", "siteIds=$($SiteInfo.Id)")
            $url = "$BaseUrl/web/api/v2.1/unified-exclusions?$($params -join '&')"
            
            $response = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $Headers -TimeoutSec 60
            
            if ($response.data -and $response.data.Count -gt 0) {
                $siteItems = $response.data | Where-Object {
                    $parts = $_.scopePath -split '\\'
                    $parts.Count -gt 2
                }
                
                return @{
                    Success    = $true
                    SiteName   = $SiteInfo.Name
                    Count      = $siteItems.Count
                    Exclusions = $siteItems
                    Error      = $null
                }
            }
            
            return @{
                Success    = $true
                SiteName   = $SiteInfo.Name
                Count      = 0
                Exclusions = @()
                Error      = $null
            }
            
        } catch {
            return @{
                Success    = $false
                SiteName   = $SiteInfo.Name
                Count      = 0
                Exclusions = @()
                Error      = $_.Exception.Message
            }
        }
    }
    
    foreach ($site in $Sites) {
        $powershell = [powershell]::Create()
        $powershell.AddScript($scriptBlock) | Out-Null
        $powershell.AddArgument($site) | Out-Null
        $powershell.AddArgument($BaseUrl) | Out-Null
        $powershell.AddArgument($Headers) | Out-Null
        $powershell.AddArgument($QueryParams) | Out-Null
        $powershell.RunspacePool = $runspacePool
        
        $runspaces += [PSCustomObject]@{
            Pipe   = $powershell
            Status = $powershell.BeginInvoke()
            Site   = $site
        }
    }
    
    $completed = 0
    $sitesWithExclusions = 0
    
    while ($runspaces | Where-Object { -not $_.Status.IsCompleted }) {
        Start-Sleep -Milliseconds 500
        
        $currentCompleted = ($runspaces | Where-Object { $_.Status.IsCompleted }).Count
        if ($currentCompleted -ne $completed) {
            $percentComplete = [Math]::Round(($currentCompleted / $Sites.Count) * 100)
            if ($currentCompleted % 50 -eq 0 -or $currentCompleted -eq $Sites.Count) {
                Write-LogMessage "Progress: $currentCompleted / $($Sites.Count) sites ($percentComplete%)" -Level "Info"
            }
            $completed = $currentCompleted
        }
    }
    
    foreach ($runspace in $runspaces) {
        try {
            $result = $runspace.Pipe.EndInvoke($runspace.Status)
            
            if ($result.Success) {
                if ($result.Count -gt 0) {
                    $exclusions += $result.Exclusions
                    $sitesWithExclusions++
                }
            } else {
                Write-LogMessage "Warning: Failed to query $($result.SiteName): $($result.Error)" -Level "Warning"
            }
            
        } catch {
            Write-LogMessage "Warning: Error processing results: $($_.Exception.Message)" -Level "Warning"
        } finally {
            $runspace.Pipe.Dispose()
        }
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    Write-LogMessage "Retrieved $($exclusions.Count) site-level exclusions from $sitesWithExclusions sites" -Level "Success"
    return $exclusions
}

function ConvertTo-EnrichedExclusion {
    param(
        [Parameter(Mandatory = $true)]
        [array]$RawExclusions,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$SiteLookup
    )
    
    Write-LogMessage "Processing $($RawExclusions.Count) exclusions..." -Level "Info"
    
    $enriched = @()
    
    foreach ($item in $RawExclusions) {
        $exclusionName = Get-SafeValue $item.exclusionName "Unnamed Exclusion"
        $type = Get-SafeValue $item.type "Unknown"
        $threatType = Get-SafeValue $item.threatType "Unknown"
        $value = Get-SafeValue $item.value "N/A"
        $pathValue = Get-SafeValue $item.pathValue "N/A"
        $description = Get-SafeValue $item.description ""
        $source = Get-SafeValue $item.source "Unknown"
        $scopePath = Get-SafeValue $item.scopePath "Unknown"
        $osType = Get-SafeValue $item.osType "N/A"
        $mode = Get-SafeValue $item.mode "N/A"
        
        $accountName = "Unknown Account"
        $siteName = "Unknown Site"
        
        if ($scopePath -ne "Unknown") {
            $pathParts = $scopePath -split '\\'
            
            if ($pathParts.Count -gt 1) {
                $firstSite = $SiteLookup.Values | Select-Object -First 1
                if ($firstSite -and $firstSite.AccountName) {
                    $accountName = $firstSite.AccountName
                } else {
                    $accountName = $pathParts[1]
                }
            }
            
            if ($pathParts.Count -gt 2) {
                $siteIdentifier = $pathParts[2]
                
                $foundSite = $null
                foreach ($siteId in $SiteLookup.Keys) {
                    if ($siteIdentifier -eq $siteId -or $siteIdentifier -like "*$siteId*") {
                        $foundSite = $SiteLookup[$siteId]
                        break
                    }
                }
                
                if ($foundSite) {
                    $siteName = $foundSite.Name
                } else {
                    $siteName = $siteIdentifier
                }
            }
        }
        
        $createdAt = "N/A"
        if ($item.createdAt) {
            try {
                $createdAt = [DateTime]::Parse($item.createdAt).ToString("yyyy-MM-dd HH:mm:ss")
            } catch {
                $createdAt = $item.createdAt
            }
        }
        
        $createdBy = Get-SafeValue $item.userName "System"
        
        $enriched += [PSCustomObject]@{
            ID            = Get-SafeValue $item.id "N/A"
            ExclusionName = $exclusionName
            Type          = Get-ExclusionTypeName -Type $type
            RawType       = $type
            ThreatType    = Get-ThreatTypeName -Type $threatType
            Value         = $value
            PathValue     = $pathValue
            Description   = $description
            Source        = $source
            ScopePath     = $scopePath
            AccountName   = $accountName
            SiteName      = $siteName
            OSType        = $osType
            Mode          = $mode
            CreatedAt     = $createdAt
            CreatedBy     = $createdBy
        }
    }
    
    Write-LogMessage "Processing complete" -Level "Success"
    return $enriched
}


function Export-ConsoleReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Exclusions,
        
        [Parameter(Mandatory = $false)]
        [switch]$GroupBySite
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SENTINELONE EXCLUSIONS REPORT" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    if ($GroupBySite) {
        $groups = $Exclusions | Group-Object -Property SiteName
    } else {
        $groups = $Exclusions | Group-Object -Property AccountName
    }
    
    foreach ($accountGroup in ($groups | Sort-Object Name)) {
        Write-Host "`n╔═══════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "║ Account: $($accountGroup.Name)" -ForegroundColor White
        Write-Host "║ Total Exclusions: $($accountGroup.Count)" -ForegroundColor Gray
        Write-Host "╚═══════════════════════════════════════" -ForegroundColor Magenta
        
        $siteGroups = $accountGroup.Group | Group-Object -Property SiteName
        
        foreach ($siteGroup in ($siteGroups | Sort-Object Name)) {
            Write-Host "`n  ┌─ Site: $($siteGroup.Name)" -ForegroundColor Yellow
            Write-Host "  │  Exclusions: $($siteGroup.Count)" -ForegroundColor Gray
            Write-Host "  └────────────────────────────────────" -ForegroundColor Yellow
            
            foreach ($exclusion in ($siteGroup.Group | Sort-Object Type, ExclusionName)) {
                Write-Host "    ├─ [$($exclusion.Type)] $($exclusion.ExclusionName)" -ForegroundColor Cyan
                Write-Host "    │  Value: $($exclusion.Value)" -ForegroundColor Gray
                Write-Host "    │  Threat Type: $($exclusion.ThreatType)" -ForegroundColor Gray
                Write-Host "    │  Source: $($exclusion.Source) | Created: $($exclusion.CreatedAt)" -ForegroundColor DarkGray
                Write-Host "    │  Created By: $($exclusion.CreatedBy)" -ForegroundColor DarkGray
                if ($exclusion.Description) {
                    Write-Host "    │  Description: $($exclusion.Description)" -ForegroundColor DarkGray
                }
                Write-Host ""
            } 
        } 
    } 
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SUMMARY STATISTICS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Exclusions: $($Exclusions.Count)" -ForegroundColor Green
    Write-Host "User-Created: $(($Exclusions | Where-Object { $_.Source -eq 'user' }).Count)" -ForegroundColor Green
    Write-Host "Path Exclusions: $(($Exclusions | Where-Object { $_.RawType -eq 'path' }).Count)" -ForegroundColor Green
    Write-Host "Hash Exclusions: $(($Exclusions | Where-Object { $_.RawType -eq 'hash' -or $_.RawType -eq 'white_hash' }).Count)" -ForegroundColor Green
    Write-Host ""
}

function Export-CsvReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Exclusions,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = Join-Path $OutputPath "S1_Exclusions_$timestamp.csv"
    
    try {
        $Exclusions | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-LogMessage "CSV exported: $csvPath" -Level "Success"
    } catch {
        Write-LogMessage "CSV export failed: $($_.Exception.Message)" -Level "Error"
    }
}

function Export-JsonReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Exclusions,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jsonPath = Join-Path $OutputPath "S1_Exclusions_$timestamp.json"
    
    try {
        $data = @{
            GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TotalCount  = $Exclusions.Count
            Exclusions  = $Exclusions
        }
        
        $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-LogMessage "JSON exported: $jsonPath" -Level "Success"
    } catch {
        Write-LogMessage "JSON export failed: $($_.Exception.Message)" -Level "Error"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Exclusions,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $htmlPath = Join-Path $OutputPath "S1_Exclusions_$timestamp.html"
    
    try {
        $generatedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $totalExclusions = $Exclusions.Count
        $userCreated = ($Exclusions | Where-Object { $_.Source -eq "user" }).Count
        $pathExclusions = ($Exclusions | Where-Object { $_.RawType -eq "path" }).Count
        
        # Build HTML report
        $html = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SentinelOne Exclusions Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #667eea; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-label { color: #666; font-size: 0.9em; }
        .stat-value { font-size: 2em; font-weight: bold; color: #333; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
        .badge-path { background: #e3f2fd; color: #1976d2; }
        .badge-hash { background: #f3e5f5; color: #7b1fa2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SentinelOne Exclusions Report</h1>
        <p>Generated: TIMESTAMP_PLACEHOLDER</p>
    </div>
    <div class="stats">
        <div class="stat-card"><div class="stat-label">Total</div><div class="stat-value">TOTAL_PLACEHOLDER</div></div>
        <div class="stat-card"><div class="stat-label">User Created</div><div class="stat-value">USER_PLACEHOLDER</div></div>
        <div class="stat-card"><div class="stat-label">Path</div><div class="stat-value">PATH_PLACEHOLDER</div></div>
        <div class="stat-card"><div class="stat-label">Accounts</div><div class="stat-value">ACCOUNTS_PLACEHOLDER</div></div>
    </div>
    <table>
        <thead><tr><th>Account</th><th>Site</th><th>Name</th><th>Type</th><th>Value</th><th>Created</th></tr></thead>
        <tbody>
'@
        
        $html = $html.Replace('TIMESTAMP_PLACEHOLDER', $generatedDate)
        $html = $html.Replace('TOTAL_PLACEHOLDER', $totalExclusions)
        $html = $html.Replace('USER_PLACEHOLDER', $userCreated)
        $html = $html.Replace('PATH_PLACEHOLDER', $pathExclusions)
        $html = $html.Replace('ACCOUNTS_PLACEHOLDER', ($Exclusions | Select-Object -Unique AccountName).Count)
        
        foreach ($exclusion in ($Exclusions | Sort-Object AccountName, SiteName)) {
            $badge = if ($exclusion.RawType -eq "path") { "badge-path" } else { "badge-hash" }
            $html += "<tr>"
            $html += "<td>$($exclusion.AccountName)</td>"
            $html += "<td>$($exclusion.SiteName)</td>"
            $html += "<td><strong>$($exclusion.ExclusionName)</strong></td>"
            $html += "<td><span class='badge $badge'>$($exclusion.Type)</span></td>"
            $html += "<td><code>$($exclusion.Value)</code></td>"
            $html += "<td>$($exclusion.CreatedAt)</td>"
            $html += "</tr>"
        }
        
        $html += "</tbody></table></body></html>"
        
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-LogMessage "HTML exported: $htmlPath" -Level "Success"
        
    } catch {
        Write-LogMessage "HTML export failed: $($_.Exception.Message)" -Level "Error"
    }
}

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SENTINELONE EXCLUSIONS REPORT" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $headers = Initialize-Headers -Token $ApiToken
    $script:siteLookup = Get-SiteLookupTable -BaseUrl $BaseUrl -Headers $headers
    
    $queryParams = @()
    
    if ($CreatedWithinDays) {
        $dateFilter = (Get-Date).AddDays(-$CreatedWithinDays)
        $isoDate = $dateFilter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $queryParams += "createdAt__gte=$isoDate"
        Write-LogMessage "Filter: Created within last $CreatedWithinDays days" -Level "Info"
    } elseif ($CreatedAfter) {
        $isoDate = $CreatedAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $queryParams += "createdAt__gte=$isoDate"
        Write-LogMessage "Filter: Created after $($CreatedAfter.ToString('yyyy-MM-dd'))" -Level "Info"
    }
    
    if (-not $IncludeSystemExclusions) {
        $queryParams += "source=user"
        Write-LogMessage "Filter: User-created exclusions only" -Level "Info"
    } elseif ($FilterSource) {
        $queryParams += "source=$FilterSource"
        Write-LogMessage "Filter: Source = $FilterSource" -Level "Info"
    }
    
    if ($FilterThreatType) {
        $queryParams += "threatType=$FilterThreatType"
        Write-LogMessage "Filter: Threat Type = $FilterThreatType" -Level "Info"
    }
    

    $sitesToQuery = @()
    $retrieveGlobal = $true
    
    if ($ClientName -or $SiteName) {
        $filterPatterns = if ($ClientName) { $ClientName } else { $SiteName }
        $sitesToQuery = Find-MatchingSites -SiteLookup $script:siteLookup -Patterns $filterPatterns
        $retrieveGlobal = $false
        
        if ($sitesToQuery.Count -eq 0) {
            Write-LogMessage "No sites found matching filter criteria" -Level "Warning"
            exit 0
        }
        
        Write-LogMessage "Found $($sitesToQuery.Count) matching sites" -Level "Success"
    } else {
        if ($GlobalOnly) {
            Write-LogMessage "GlobalOnly mode - skipping site enumeration" -Level "Info"
        } else {
            $sitesToQuery = $script:siteLookup.GetEnumerator() | ForEach-Object {
                @{
                    Id          = $_.Key
                    Name        = $_.Value.Name
                    AccountName = $_.Value.AccountName
                }
            }
        }
    }
    
    # Retrieve exclusions
    if ($retrieveGlobal) {
        $globalExclusions = Get-GlobalExclusions -BaseUrl $BaseUrl -Headers $headers -QueryParams $queryParams
        $script:allExclusions += $globalExclusions
    }
    
    if ($sitesToQuery.Count -gt 0) {
        $siteExclusions = Get-SiteExclusions -Sites $sitesToQuery -BaseUrl $BaseUrl -Headers $headers -QueryParams $queryParams -MaxThreads $MaxThreads
        $script:allExclusions += $siteExclusions
    }
    
    if ($script:allExclusions.Count -eq 0) {
        Write-LogMessage "No exclusions found" -Level "Warning"
        exit 0
    }
    
    Write-LogMessage "`nTotal exclusions retrieved: $($script:allExclusions.Count)" -Level "Success"
    
    $script:enrichedExclusions = ConvertTo-EnrichedExclusion -RawExclusions $script:allExclusions -SiteLookup $script:siteLookup

    if ($ExportFormat -eq "Console" -or $ExportFormat -eq "All") {
        Export-ConsoleReport -Exclusions $script:enrichedExclusions -GroupBySite:$GroupBySite
    }
    
    if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "All") {
        Export-CsvReport -Exclusions $script:enrichedExclusions -OutputPath $OutputPath
    }
    
    if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "All") {
        Export-JsonReport -Exclusions $script:enrichedExclusions -OutputPath $OutputPath
    }
    
    if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "All") {
        Export-HtmlReport -Exclusions $script:enrichedExclusions -OutputPath $OutputPath
    }
    
    Write-LogMessage "`nReport generation completed successfully!" -Level "Success"
    
} catch {
    Write-Host "ERROR occurred" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
