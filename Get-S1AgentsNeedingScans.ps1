<#
.SYNOPSIS
    Get agents that need scanning based on last successful scan date.

.DESCRIPTION
    This script retrieves all active SentinelOne agents that haven't had a successful scan within
    a specified timeframe. It provides comprehensive statistics, filtering capabilities, and multiple
    export formats. The script handles pagination automatically and provides progress updates.
    
    By default, the script looks for agents that haven't scanned in the past 90 days, but this is
    configurable. Only active agents are included in the results.

.PARAMETER BaseURL
    The base URL of your SentinelOne console (e.g., "https://usea1-swprd1.sentinelone.net")

.PARAMETER APIToken
    Your SentinelOne API token

.PARAMETER DaysWithoutScan
    Optional. Number of days since last successful scan to filter by. Default: 90

.PARAMETER SiteIds
    Optional. Array of Site IDs to filter by.

.PARAMETER GroupIds
    Optional. Array of Group IDs to filter by.

.PARAMETER OSTypes
    Optional. Array of OS types to filter by. Valid values: "windows", "linux", "macos", "windows_legacy"

.PARAMETER MachineTypes
    Optional. Array of machine types to filter by. 
    Valid values: "desktop", "laptop", "server", "kubernetes pod", "ecs task", "kubernetes helper", "unknown"

.PARAMETER OutputFormat
    Optional. Output format: "Console", "CSV", "JSON", "HTML", or "All". Default: "Console"

.PARAMETER OutputPath
    Optional. Path for output files when using CSV, JSON, or HTML formats.
    Default: Current directory with timestamp.

.PARAMETER Limit
    Optional. Number of results per page (1-1000). Default: 100

.EXAMPLE
    Get-S1AgentsNeedingScans.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken"
    
    Gets all agents that haven't scanned in the past 90 days (default).

.EXAMPLE
    Get-S1AgentsNeedingScans.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -DaysWithoutScan 30 -OutputFormat "All"
    
    Gets agents without scans in past 30 days and exports to all formats.

.EXAMPLE
    Get-S1AgentsNeedingScans.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -OSTypes @("windows") -MachineTypes @("server") -OutputFormat "CSV"
    
    Gets Windows servers that need scanning and exports to CSV.

.EXAMPLE
    Get-S1AgentsNeedingScans.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -DaysWithoutScan 180 -OutputFormat "HTML"
    
    Gets agents without scans in past 6 months and generates an HTML report.

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
    [int]$DaysWithoutScan = 90,
    
    [Parameter(Mandatory=$false)]
    [string[]]$SiteIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupIds,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("windows", "linux", "macos", "windows_legacy")]
    [string[]]$OSTypes,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("desktop", "laptop", "server", "kubernetes pod", "ecs task", "kubernetes helper", "unknown")]
    [string[]]$MachineTypes,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "All")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$Limit = 100
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location) "S1_AgentsNeedingScans_$timestamp"
}

# Cutoff date
$cutoffDate = (Get-Date).AddDays(-$DaysWithoutScan)
$cutoffDateISO = $cutoffDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SentinelOne Agents Needing Scans Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cutoff Date: $cutoffDate ($DaysWithoutScan days ago)" -ForegroundColor Yellow
if ($OSTypes) { Write-Host "OS Filter: $($OSTypes -join ', ')" -ForegroundColor Yellow }
if ($MachineTypes) { Write-Host "Machine Types: $($MachineTypes -join ', ')" -ForegroundColor Yellow }

$headers = @{
    "Authorization" = "ApiToken $APIToken"
    "Content-Type" = "application/json"
}

$filter = @{
    "lastSuccessfulScanDate__lt" = $cutoffDateISO
    "isActive" = "true"
}

if ($SiteIds) { $filter["siteIds"] = $SiteIds -join "," }
if ($GroupIds) { $filter["groupIds"] = $GroupIds -join "," }
if ($OSTypes) { $filter["osTypes"] = $OSTypes -join "," }
if ($MachineTypes) { $filter["machineTypes"] = $MachineTypes -join "," }

$allAgents = @()
$cursor = $null
$pageCount = 1

Write-Host "`nRetrieving agents from SentinelOne..." -ForegroundColor Yellow

try {
    do {
        $queryParams = @()
        foreach ($key in $filter.Keys) {
            $queryParams += "$key=$($filter[$key])"
        }
        $queryParams += "limit=$Limit"
        
        if ($cursor) {
            $queryParams += "cursor=$cursor"
        }
        
        $agentsUrl = "$BaseURL/web/api/v2.1/agents?" + ($queryParams -join "&")
        
        Write-Host "  Fetching page $pageCount..." -ForegroundColor Gray
        
        $agentsResponse = Invoke-RestMethod -Uri $agentsUrl -Method 'GET' -Headers $headers
        
        # Check for agent data
        if ($null -ne $agentsResponse.data -and $agentsResponse.data.Count -gt 0) {
            $allAgents += $agentsResponse.data
            
            Write-Host "    Retrieved $($agentsResponse.data.Count) agents (Total: $($allAgents.Count))" -ForegroundColor Gray
            
            # Pagination
            if ($null -ne $agentsResponse.pagination -and $null -ne $agentsResponse.pagination.nextCursor) {
                $cursor = $agentsResponse.pagination.nextCursor
                $pageCount++
            } else {
                $cursor = $null
            }
        } else {
            $cursor = $null
        }
        
    } while ($null -ne $cursor -and $cursor -ne "null")
    
    Write-Host "`nTotal agents retrieved: $($allAgents.Count)" -ForegroundColor Green
    
    $agentsNeedingScans = @()
    
    Write-Host "Processing agent data..." -ForegroundColor Yellow
    
    foreach ($agent in $allAgents) {
        $lastScanDate = if ($agent.lastSuccessfulScanDate) { 
            try {
                [DateTime]::Parse($agent.lastSuccessfulScanDate)
            } catch {
                $null
            }
        } else { 
            $null
        }
        
        $daysSinceLastScan = if ($lastScanDate) {
            [math]::Round(((Get-Date) - $lastScanDate).TotalDays, 1)
        } else {
            "Never"
        }
        
        $agentInfo = [PSCustomObject]@{
            ComputerName = if ($agent.computerName) { $agent.computerName } else { "N/A" }
            SiteName = if ($agent.siteName) { $agent.siteName } else { "N/A" }
            GroupName = if ($agent.groupName) { $agent.groupName } else { "N/A" }
            OSName = if ($agent.osName) { $agent.osName } else { "N/A" }
            MachineType = if ($agent.machineType) { $agent.machineType } else { "N/A" }
            LastScanDate = if ($lastScanDate) { $lastScanDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            DaysSinceLastScan = $daysSinceLastScan
            AgentVersion = if ($agent.agentVersion) { $agent.agentVersion } else { "N/A" }
            IsActive = if ($null -ne $agent.isActive) { $agent.isActive } else { "N/A" }
            AgentID = if ($agent.id) { $agent.id } else { "N/A" }
            NetworkStatus = if ($agent.networkStatus) { $agent.networkStatus } else { "N/A" }
            LastActiveDate = if ($agent.lastActiveDate) { $agent.lastActiveDate } else { "N/A" }
            Domain = if ($agent.domain) { $agent.domain } else { "N/A" }
        }
        $agentsNeedingScans += $agentInfo
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Summary Statistics" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Agents Needing Scans: $($agentsNeedingScans.Count)" -ForegroundColor Green
    Write-Host "Agents Never Scanned: $(($agentsNeedingScans | Where-Object { $_.LastScanDate -eq 'Never' }).Count)" -ForegroundColor Yellow
    
    # Stats
    $sitesStats = $agentsNeedingScans | Group-Object -Property SiteName | 
        Select-Object @{Name="Site"; Expression={$_.Name}}, 
                      @{Name="Count"; Expression={$_.Count}} | 
        Sort-Object Count -Descending
    
    $osStats = $agentsNeedingScans | Group-Object -Property OSName | 
        Select-Object @{Name="OS"; Expression={$_.Name}}, 
                      @{Name="Count"; Expression={$_.Count}} | 
        Sort-Object Count -Descending
    
    $machineTypeStats = $agentsNeedingScans | Group-Object -Property MachineType | 
        Select-Object @{Name="Type"; Expression={$_.Name}}, 
                      @{Name="Count"; Expression={$_.Count}} | 
        Sort-Object Count -Descending
    
    # Display console output
    if ($OutputFormat -eq "Console" -or $OutputFormat -eq "All") {
        Write-Host "`nAgents Needing Scans (Top 50):" -ForegroundColor Cyan
        $agentsNeedingScans | Select-Object -First 50 | 
            Sort-Object DaysSinceLastScan -Descending | 
            Format-Table -Property ComputerName, SiteName, OSName, MachineType, LastScanDate, DaysSinceLastScan, NetworkStatus -AutoSize
        
        if ($agentsNeedingScans.Count -gt 50) {
            Write-Host "Showing top 50 agents. Total agents needing scans: $($agentsNeedingScans.Count)" -ForegroundColor Yellow
        }
        
        Write-Host "`nBreakdown by Site:" -ForegroundColor Cyan
        $sitesStats | Select-Object -First 20 | Format-Table -AutoSize
        
        Write-Host "`nBreakdown by OS:" -ForegroundColor Cyan
        $osStats | Format-Table -AutoSize
        
        Write-Host "`nBreakdown by Machine Type:" -ForegroundColor Cyan
        $machineTypeStats | Format-Table -AutoSize
    }
    
    # CSV export
    if ($OutputFormat -in @("CSV", "All")) {
        Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
        
        $agentsFile = "${OutputPath}_Agents.csv"
        $agentsNeedingScans | Export-Csv -Path $agentsFile -NoTypeInformation
        Write-Host "  Agents exported to: $agentsFile" -ForegroundColor Green
        
        $sitesFile = "${OutputPath}_SiteStats.csv"
        $sitesStats | Export-Csv -Path $sitesFile -NoTypeInformation
        Write-Host "  Site statistics exported to: $sitesFile" -ForegroundColor Green

        $osFile = "${OutputPath}_OSStats.csv"
        $osStats | Export-Csv -Path $osFile -NoTypeInformation
        Write-Host "  OS statistics exported to: $osFile" -ForegroundColor Green
    }
    
    # JSON export
    if ($OutputFormat -in @("JSON", "All")) {
        Write-Host "`nExporting to JSON..." -ForegroundColor Yellow
        
        $jsonData = @{
            Summary = @{
                CutoffDate = $cutoffDate.ToString("yyyy-MM-dd HH:mm:ss")
                DaysWithoutScan = $DaysWithoutScan
                TotalAgents = $agentsNeedingScans.Count
                AgentsNeverScanned = ($agentsNeedingScans | Where-Object { $_.LastScanDate -eq 'Never' }).Count
            }
            Agents = $agentsNeedingScans
            Statistics = @{
                Sites = $sitesStats
                OperatingSystems = $osStats
                MachineTypes = $machineTypeStats
            }
        }
        
        $jsonFile = "${OutputPath}.json"
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Host "  JSON exported to: $jsonFile" -ForegroundColor Green
    }
    
    # HTML export
    if ($OutputFormat -in @("HTML", "All")) {
        Write-Host "`nExporting to HTML..." -ForegroundColor Yellow

        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>SentinelOne Agents Needing Scans Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .subtitle { margin-top: 10px; opacity: 0.9; font-size: 1.1em; }
        .summary { background: white; padding: 20px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 15px; }
        .summary-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .summary-item .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .summary-item .label { color: #666; margin-top: 5px; }
        .section { background: white; margin-bottom: 30px; padding: 25px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f8f9fa; }
        .warning { color: #d9534f; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128681; SentinelOne Agents Needing Scans Report</h1>
        <div class="subtitle">Cutoff Date: $($cutoffDate.ToString("yyyy-MM-dd HH:mm:ss")) ($DaysWithoutScan days ago)</div>
        <div class="subtitle">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value">$($agentsNeedingScans.Count)</div>
                <div class="label">Agents Needing Scans</div>
            </div>
            <div class="summary-item">
                <div class="value">$(($agentsNeedingScans | Where-Object { $_.LastScanDate -eq 'Never' }).Count)</div>
                <div class="label">Never Scanned</div>
            </div>
            <div class="summary-item">
                <div class="value">$($sitesStats.Count)</div>
                <div class="label">Affected Sites</div>
            </div>
            <div class="summary-item">
                <div class="value">$DaysWithoutScan</div>
                <div class="label">Days Threshold</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>&#128202; Breakdown by Site</h2>
        <table>
            <thead>
                <tr>
                    <th>Site</th>
                    <th>Agent Count</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $sitesStats) {
            $htmlContent += "<tr><td>$($stat.Site)</td><td>$($stat.Count)</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>&#128421;&#65039; Breakdown by Operating System</h2>
        <table>
            <thead>
                <tr>
                    <th>Operating System</th>
                    <th>Agent Count</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $osStats) {
            $htmlContent += "<tr><td>$($stat.OS)</td><td>$($stat.Count)</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>&#128187; Breakdown by Machine Type</h2>
        <table>
            <thead>
                <tr>
                    <th>Machine Type</th>
                    <th>Agent Count</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $machineTypeStats) {
            $htmlContent += "<tr><td>$($stat.Type)</td><td>$($stat.Count)</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>&#128218; Agent Details (Top 100)</h2>
        <table>
            <thead>
                <tr>
                    <th>Computer Name</th>
                    <th>Site</th>
                    <th>OS</th>
                    <th>Type</th>
                    <th>Last Scan</th>
                    <th>Days Since Scan</th>
                    <th>Network Status</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($agent in ($agentsNeedingScans | Sort-Object DaysSinceLastScan -Descending | Select-Object -First 100)) {
            $daysClass = if ($agent.LastScanDate -eq "Never") { "class='warning'" } else { "" }
            $htmlContent += "<tr><td>$($agent.ComputerName)</td><td>$($agent.SiteName)</td><td>$($agent.OSName)</td><td>$($agent.MachineType)</td><td $daysClass>$($agent.LastScanDate)</td><td $daysClass>$($agent.DaysSinceLastScan)</td><td>$($agent.NetworkStatus)</td></tr>`n"
        }
        
        $currentYear = (Get-Date).Year
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>Report generated by SentinelOne Agents Needing Scans Script</p>
        <p>Advanced Microelectronics Inc. | $currentYear</p>
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
    
    return $agentsNeedingScans
    
} catch {
    Write-Host "`nError occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
