<#
.SYNOPSIS
    Retrieve SentinelOne configuration overrides with detailed reporting capabilities.

.DESCRIPTION
    This script retrieves configuration overrides from the SentinelOne console, providing detailed 
    analysis and reporting of configuration customizations across your environment. Configuration 
    overrides allow you to customize agent behavior for specific accounts, sites, groups, or 
    individual agents. The script handles pagination automatically and provides comprehensive 
    statistics with multiple export formats.
    
    Configuration overrides are used to customize agent settings beyond the default policy, such as
    exclusions, scan settings, network configurations, and behavioral detections.

.PARAMETER BaseURL
    The base URL of your SentinelOne console (e.g., "https://usea1-swprd1.sentinelone.net")

.PARAMETER APIToken
    Your SentinelOne API token

.PARAMETER AccountIds
    Optional. Array of Account IDs to filter by.

.PARAMETER AgentIds
    Optional. Array of Agent IDs to filter by.

.PARAMETER AgentVersions
    Optional. Array of agent versions to include.

.PARAMETER SiteIds
    Optional. Array of Site IDs to filter by.

.PARAMETER GroupIds
    Optional. Array of Group IDs to filter by.

.PARAMETER OsTypes
    Optional. Array of OS types to include. Valid values: "windows", "linux", "macos", "windows_legacy"

.PARAMETER Query
    Optional. Free text search on fields: name, description, agent_version, os_type, config.

.PARAMETER NameLike
    Optional. Match name partially (substring match).

.PARAMETER DescriptionLike
    Optional. Match description partially (substring match).

.PARAMETER CreatedAfter
    Optional. Config overrides created after this timestamp.

.PARAMETER CreatedBefore
    Optional. Config overrides created before this timestamp.

.PARAMETER OutputFormat
    Optional. Output format: "Console", "CSV", "JSON", "HTML", or "All". Default: "Console"

.PARAMETER OutputPath
    Optional. Path for output files when using CSV, JSON, or HTML formats.
    Default: Current directory with timestamp.

.PARAMETER Limit
    Optional. Number of results per page (1-1000). Default: 1000

.PARAMETER Tenant
    Optional. Indicates a tenant scope request.

.EXAMPLE
    Get-S1ConfigOverrides.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken"
    
    Retrieves all config overrides and displays in console.

.EXAMPLE
    Get-S1ConfigOverrides.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -OutputFormat "All"
    
    Retrieves all config overrides and exports to all formats (Console, CSV, JSON, HTML).

.EXAMPLE
    Get-S1ConfigOverrides.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -OsTypes @("windows") -OutputFormat "HTML"
    
    Retrieves Windows config overrides and generates HTML report.

.EXAMPLE
    Get-S1ConfigOverrides.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -Query "exclusion" -OutputFormat "CSV"
    
    Searches for config overrides containing "exclusion" and exports to CSV.

.EXAMPLE
    Get-S1ConfigOverrides.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -NameLike "security" -OutputFormat "All"
    
    Retrieves config overrides with names containing "security" and exports to all formats.

.NOTES
    Author: Geoff Tankersley
    Requires: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$BaseURL,
    
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AccountIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AgentIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AgentVersions,
    
    [Parameter(Mandatory=$false)]
    [string[]]$SiteIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupIds,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("windows", "linux", "macos", "windows_legacy")]
    [string[]]$OsTypes,
    
    [Parameter(Mandatory=$false)]
    [string]$Query,
    
    [Parameter(Mandatory=$false)]
    [string]$NameLike,
    
    [Parameter(Mandatory=$false)]
    [string]$DescriptionLike,
    
    [Parameter(Mandatory=$false)]
    [datetime]$CreatedAfter,
    
    [Parameter(Mandatory=$false)]
    [datetime]$CreatedBefore,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "All")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$Limit = 1000,
    
    [Parameter(Mandatory=$false)]
    [switch]$Tenant
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location) "S1_ConfigOverrides_$timestamp"
}

$BaseURL = $BaseURL.TrimEnd('/')

try {
    $null = [System.Uri]$BaseURL
} catch {
    throw "Invalid BaseURL format: $BaseURL. Please ensure it's a valid URI (e.g., https://yourinstance.sentinelone.net)"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SentinelOne Config Overrides Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$headers = @{
    "Authorization" = "ApiToken $APIToken"
    "Content-Type" = "application/json"
}

$allResults = @()
$cursor = $null
$pageCount = 1

Write-Host "`nRetrieving config overrides from SentinelOne..." -ForegroundColor Yellow

try {
    do {
        $queryParams = @{}
        
        if ($AccountIds) { $queryParams['accountIds'] = $AccountIds -join ',' }
        if ($AgentIds) { $queryParams['agentIds'] = $AgentIds -join ',' }
        if ($AgentVersions) { $queryParams['agentVersions'] = $AgentVersions -join ',' }
        if ($SiteIds) { $queryParams['siteIds'] = $SiteIds -join ',' }
        if ($GroupIds) { $queryParams['groupIds'] = $GroupIds -join ',' }
        if ($OsTypes) { $queryParams['osTypes'] = $OsTypes -join ',' }
        if ($Query) { $queryParams['query'] = $Query }
        if ($NameLike) { $queryParams['name__like'] = $NameLike }
        if ($DescriptionLike) { $queryParams['description__like'] = $DescriptionLike }
        if ($CreatedAfter) { $queryParams['createdAt__gte'] = $CreatedAfter.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
        if ($CreatedBefore) { $queryParams['createdAt__lte'] = $CreatedBefore.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
        if ($Tenant) { $queryParams['tenant'] = 'true' }
        
        $queryParams['limit'] = $Limit
        $queryParams['skipCount'] = 'false'
        
        if ($cursor) {
            $queryParams['cursor'] = $cursor
        }
        
        $uri = "$BaseURL/web/api/v2.1/config-override"
        
        if ($queryParams.Count -gt 0) {
            $queryString = ($queryParams.GetEnumerator() | ForEach-Object { 
                "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value.ToString()))" 
            }) -join '&'
            $fullUri = "$uri`?$queryString"
        } else {
            $fullUri = $uri
        }
        
        Write-Host "  Fetching page $pageCount..." -ForegroundColor Gray
        
        $response = Invoke-RestMethod -Uri $fullUri -Headers $headers -Method Get
        
        if ($response.data) {
            $allResults += $response.data
            Write-Host "    Retrieved $($response.data.Count) config overrides (Total: $($allResults.Count))" -ForegroundColor Gray
        }
        
        if ($null -ne $response.pagination -and $null -ne $response.pagination.nextCursor) {
            $cursor = $response.pagination.nextCursor
            $pageCount++
        } else {
            $cursor = $null
        }
        
    } while ($cursor)
    
    Write-Host "`nTotal config overrides retrieved: $($allResults.Count)" -ForegroundColor Green
    
    if ($allResults.Count -eq 0) {
        Write-Host "No config overrides found matching the specified criteria." -ForegroundColor Yellow
        return
    }
    
    $osTypeStats = $allResults | Group-Object osType | 
                   Sort-Object Count -Descending | 
                   Select-Object @{Name="OS Type"; Expression={$_.Name}}, Count, 
                                 @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $scopeStats = $allResults | Group-Object scope | 
                  Sort-Object Count -Descending | 
                  Select-Object @{Name="Scope"; Expression={$_.Name}}, Count, 
                                @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $accountStats = $allResults | Group-Object {$_.account.name} | 
                    Sort-Object Count -Descending | 
                    Select-Object @{Name="Account"; Expression={$_.Name}}, Count, 
                                  @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $siteStats = $allResults | Where-Object { $_.site.name } | 
                 Group-Object {$_.site.name} | 
                 Sort-Object Count -Descending | 
                 Select-Object @{Name="Site"; Expression={$_.Name}}, Count, 
                               @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $groupStats = $allResults | Where-Object { $_.group.name } | 
                  Group-Object {$_.group.name} | 
                  Sort-Object Count -Descending | 
                  Select-Object @{Name="Group"; Expression={$_.Name}}, Count, 
                                @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $agentVersionStats = $allResults | Where-Object { $_.agentVersion } | 
                         Group-Object agentVersion | 
                         Sort-Object Count -Descending | 
                         Select-Object @{Name="Agent Version"; Expression={$_.Name}}, Count, 
                                       @{Name="Percentage"; Expression={[math]::Round(($_.Count / $allResults.Count) * 100, 2)}}
    
    $uniqueOSTypes = ($osTypeStats | Measure-Object).Count
    $uniqueAccounts = ($accountStats | Measure-Object).Count
    $uniqueSites = ($siteStats | Measure-Object).Count
    $uniqueGroups = ($groupStats | Measure-Object).Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Summary Statistics" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Config Overrides: $($allResults.Count)" -ForegroundColor Green
    Write-Host "Unique OS Types: $uniqueOSTypes" -ForegroundColor White
    Write-Host "Unique Accounts: $uniqueAccounts" -ForegroundColor White
    Write-Host "Unique Sites: $uniqueSites" -ForegroundColor White
    Write-Host "Unique Groups: $uniqueGroups" -ForegroundColor White
    
    if ($OutputFormat -eq "Console" -or $OutputFormat -eq "All") {
        Write-Host "`nDistribution by OS Type:" -ForegroundColor Cyan
        $osTypeStats | Format-Table -AutoSize
        
        Write-Host "`nDistribution by Scope:" -ForegroundColor Cyan
        $scopeStats | Format-Table -AutoSize
        
        Write-Host "`nDistribution by Account (Top 20):" -ForegroundColor Cyan
        $accountStats | Select-Object -First 20 | Format-Table -AutoSize
        
        if ($siteStats.Count -gt 0) {
            Write-Host "`nDistribution by Site (Top 20):" -ForegroundColor Cyan
            $siteStats | Select-Object -First 20 | Format-Table -AutoSize
        }
        
        if ($groupStats.Count -gt 0) {
            Write-Host "`nDistribution by Group (Top 20):" -ForegroundColor Cyan
            $groupStats | Select-Object -First 20 | Format-Table -AutoSize
        }
        
        if ($agentVersionStats.Count -gt 0) {
            Write-Host "`nDistribution by Agent Version:" -ForegroundColor Cyan
            $agentVersionStats | Format-Table -AutoSize
        }
        
        Write-Host "`nConfig Overrides Details (Top 50):" -ForegroundColor Cyan
        $allResults | Select-Object -First 50 | 
            Select-Object name, description, osType, scope, 
                         @{Name="Account"; Expression={$_.account.name}}, 
                         @{Name="Site"; Expression={$_.site.name}}, 
                         @{Name="Group"; Expression={$_.group.name}}, 
                         agentVersion | 
            Format-Table -AutoSize
        
        if ($allResults.Count -gt 50) {
            Write-Host "Showing top 50 config overrides. Total: $($allResults.Count)" -ForegroundColor Yellow
        }
    }
    
    if ($OutputFormat -in @("CSV", "All")) {
        Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
        
        $csvData = $allResults | Select-Object name, description, osType, scope, 
                                              @{Name="Account"; Expression={$_.account.name}}, 
                                              @{Name="AccountId"; Expression={$_.account.id}}, 
                                              @{Name="Site"; Expression={$_.site.name}}, 
                                              @{Name="SiteId"; Expression={$_.site.id}}, 
                                              @{Name="Group"; Expression={$_.group.name}}, 
                                              @{Name="GroupId"; Expression={$_.group.id}}, 
                                              agentVersion, 
                                              @{Name="CreatedAt"; Expression={$_.createdAt}}, 
                                              @{Name="UpdatedAt"; Expression={$_.updatedAt}}, 
                                              id
        
        $overridesFile = "${OutputPath}_Overrides.csv"
        $csvData | Export-Csv -Path $overridesFile -NoTypeInformation
        Write-Host "  Config overrides exported to: $overridesFile" -ForegroundColor Green
        
        $osStatsFile = "${OutputPath}_OSStats.csv"
        $osTypeStats | Export-Csv -Path $osStatsFile -NoTypeInformation
        Write-Host "  OS statistics exported to: $osStatsFile" -ForegroundColor Green
        
        $accountStatsFile = "${OutputPath}_AccountStats.csv"
        $accountStats | Export-Csv -Path $accountStatsFile -NoTypeInformation
        Write-Host "  Account statistics exported to: $accountStatsFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("JSON", "All")) {
        Write-Host "`nExporting to JSON..." -ForegroundColor Yellow
        
        $jsonData = @{
            Summary = @{
                TotalOverrides = $allResults.Count
                UniqueAccounts = $accountStats.Count
                UniqueSites = $siteStats.Count
                UniqueGroups = $groupStats.Count
                OSTypes = $osTypeStats.Count
                GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            ConfigOverrides = $allResults
            Statistics = @{
                OSTypes = $osTypeStats
                Scopes = $scopeStats
                Accounts = $accountStats
                Sites = $siteStats
                Groups = $groupStats
            }
        }
        
        $jsonFile = "${OutputPath}.json"
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Host "  JSON exported to: $jsonFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("HTML", "All")) {
        Write-Host "`nExporting to HTML..." -ForegroundColor Yellow
        
        $currentYear = (Get-Date).Year
        
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelOne Config Overrides Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 3px solid #007acc; }
        .header h1 { color: #007acc; margin: 0; font-size: 2.5em; }
        .header p { color: #666; margin: 10px 0; font-size: 1.1em; }
        .summary-box { background: linear-gradient(135deg, #007acc, #0056b3); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; }
        .summary-box h2 { margin: 0 0 10px 0; }
        .summary-box .count { font-size: 3em; font-weight: bold; margin: 10px 0; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #007acc; border-bottom: 2px solid #007acc; padding-bottom: 10px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; word-wrap: break-word; max-width: 300px; }
        th { background-color: #007acc; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f5f5f5; }
        .metric-card { display: inline-block; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; margin: 10px; min-width: 200px; text-align: center; }
        .metric-card h3 { margin: 0 0 10px 0; color: #007acc; }
        .metric-card .value { font-size: 2em; font-weight: bold; color: #333; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
        .grid-4 { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid-4 { grid-template-columns: 1fr; } }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-windows { background-color: #0078d4; color: white; }
        .badge-linux { background-color: #ff6b35; color: white; }
        .badge-macos { background-color: #000000; color: white; }
        .badge-group { background-color: #28a745; color: white; }
        .badge-agent { background-color: #6c757d; color: white; }
        .badge-site { background-color: #17a2b8; color: white; }
        .badge-account { background-color: #ffc107; color: #333; }
        .config-preview { max-width: 400px; font-family: monospace; font-size: 0.75em; background-color: #f8f9fa; padding: 5px; border-radius: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SentinelOne Config Overrides Report</h1>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="summary-box">
            <h2>Total Config Overrides</h2>
            <div class="count">$($allResults.Count)</div>
        </div>
        
        <div class="section">
            <h2>📊 Summary Statistics</h2>
            <div class="grid-4">
                <div class="metric-card">
                    <h3>Total Overrides</h3>
                    <div class="value">$($allResults.Count)</div>
                </div>
                <div class="metric-card">
                    <h3>Unique OS Types</h3>
                    <div class="value">$uniqueOSTypes</div>
                </div>
                <div class="metric-card">
                    <h3>Unique Accounts</h3>
                    <div class="value">$uniqueAccounts</div>
                </div>
                <div class="metric-card">
                    <h3>Unique Sites</h3>
                    <div class="value">$uniqueSites</div>
                </div>
            </div>
            <div class="grid-4" style="margin-top: 20px;">
                <div class="metric-card">
                    <h3>Unique Groups</h3>
                    <div class="value">$uniqueGroups</div>
                </div>
                <div class="metric-card">
                    <h3>Agent Versions</h3>
                    <div class="value">$(($agentVersionStats | Measure-Object).Count)</div>
                </div>
                <div class="metric-card">
                    <h3>Scope Types</h3>
                    <div class="value">$(($scopeStats | Measure-Object).Count)</div>
                </div>
                <div class="metric-card">
                    <h3>&nbsp;</h3>
                    <div class="value" style="font-size: 1em;">&nbsp;</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>💻 Distribution by OS Type</h2>
            <table>
                <thead>
                    <tr>
                        <th>OS Type</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($stat in $osTypeStats) {
            $htmlContent += "<tr><td>$($stat.'OS Type')</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
        }
        
        $htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🎯 Distribution by Scope</h2>
            <table>
                <thead>
                    <tr>
                        <th>Scope</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($stat in $scopeStats) {
            $htmlContent += "<tr><td>$($stat.Scope)</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
        }
        
        $htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🏢 Distribution by Account</h2>
            <table>
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($stat in ($accountStats | Select-Object -First 20)) {
            $htmlContent += "<tr><td>$($stat.Account)</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
        }
        
        $htmlContent += @"
                </tbody>
            </table>
        </div>
"@
        
        if ($siteStats.Count -gt 0) {
            $htmlContent += @"
        
        <div class="section">
            <h2>🏛️ Distribution by Site (Top 20)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Site</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
            
            foreach ($stat in ($siteStats | Select-Object -First 20)) {
                $htmlContent += "<tr><td>$($stat.Site)</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
            }
            
            $htmlContent += @"
                </tbody>
            </table>
        </div>
"@
        }
        
        if ($groupStats.Count -gt 0) {
            $htmlContent += @"
        
        <div class="section">
            <h2>👥 Distribution by Group (Top 20)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Group</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
            
            foreach ($stat in ($groupStats | Select-Object -First 20)) {
                $htmlContent += "<tr><td>$($stat.Group)</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
            }
            
            $htmlContent += @"
                </tbody>
            </table>
        </div>
"@
        }
        
        if ($agentVersionStats.Count -gt 0) {
            $htmlContent += @"
        
        <div class="section">
            <h2>🔧 Distribution by Agent Version</h2>
            <table>
                <thead>
                    <tr>
                        <th>Agent Version</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
"@
            
            foreach ($stat in $agentVersionStats) {
                $htmlContent += "<tr><td>$($stat.'Agent Version')</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
            }
            
            $htmlContent += @"
                </tbody>
            </table>
        </div>
"@
        }
        
        $htmlContent += @"
            <h2>📋 Config Overrides Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Description</th>
                        <th>OS Type</th>
                        <th>Scope</th>
                        <th>Account</th>
                        <th>Site</th>
                        <th>Group</th>
                        <th>Agent Version</th>
                        <th>Created</th>
                        <th>Config Details</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($override in $allResults) {
            $osTypeBadge = switch ($override.osType) {
                'windows' { 'badge-windows' }
                'linux' { 'badge-linux' }
                'macos' { 'badge-macos' }
                default { 'badge-linux' }
            }
            
            $scopeBadge = switch ($override.scope) {
                'group' { 'badge-group' }
                'agent' { 'badge-agent' }
                'site' { 'badge-site' }
                'account' { 'badge-account' }
                default { 'badge-group' }
            }
            
            $createdAt = if ($override.createdAt) {
                try {
                    [DateTime]::Parse($override.createdAt).ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $override.createdAt
                }
            } else {
                "N/A"
            }
            
            $configDetails = if ($override.config) {
                $configJson = $override.config | ConvertTo-Json -Depth 5 -Compress
                if ($configJson.Length -gt 200) {
                    $configJson.Substring(0, 197) + "..."
                } else {
                    $configJson
                }
            } else {
                "N/A"
            }
            
            $htmlContent += @"
                <tr>
                    <td><strong>$($override.name)</strong></td>
                    <td>$($override.description)</td>
                    <td><span class="badge $osTypeBadge">$($override.osType)</span></td>
                    <td><span class="badge $scopeBadge">$($override.scope)</span></td>
                    <td>$($override.account.name)</td>
                    <td>$($override.site.name)</td>
                    <td>$($override.group.name)</td>
                    <td>$($override.agentVersion)</td>
                    <td>$createdAt</td>
                    <td><div class="config-preview" style="max-width:300px; word-wrap:break-word;" title="$([System.Web.HttpUtility]::HtmlAttributeEncode($configDetails))">$configDetails</div></td>
                </tr>
"@
        }
        
        $htmlContent += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated by SentinelOne Config Overrides Script</p>
            <p>$currentYear</p>
        </div>
    </div>
</body>
</html>
"@
        
        $htmlFile = "${OutputPath}.html"
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        Write-Host "  HTML report exported to: $htmlFile" -ForegroundColor Green
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Processing Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    return $allResults
    
} catch {
    Write-Host "`nError occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
