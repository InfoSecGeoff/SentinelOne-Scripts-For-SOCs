<#
.SYNOPSIS
    Retrieves SentinelOne threats marked as suspicious or true positive from the past 30 days.

.DESCRIPTION
    This script retrieves all threats from SentinelOne that have been marked with analyst verdicts
    of "suspicious" or "true_positive" from the past 30 days. It provides comprehensive threat details
    and can export to multiple formats for analysis and reporting.

.PARAMETER BaseURL
    The base URL of your SentinelOne console (e.g., "https://your-instance.sentinelone.net")

.PARAMETER APIToken
    Your SentinelOne API token

.PARAMETER Days
    Optional. Number of days to look back. Default: 30

.PARAMETER AnalystVerdicts
    Optional. Array of analyst verdicts to filter by. Valid values: "true_positive", "suspicious", "false_positive", "undefined"
    Default: "true_positive", "suspicious"

.PARAMETER SiteIds
    Optional. Array of Site IDs to filter by.

.PARAMETER AccountIds
    Optional. Array of Account IDs to filter by.

.PARAMETER ConfidenceLevels
    Optional. Array of confidence levels to filter by. Valid values: "malicious", "suspicious", "n/a"

.PARAMETER IncidentStatuses
    Optional. Array of incident statuses to filter by. Valid values: "unresolved", "in_progress", "resolved"

.PARAMETER OutputFormat
    Optional. Output format: "Console", "CSV", "JSON", "HTML", or "All". Default: "Console"

.PARAMETER OutputPath
    Optional. Path for output files when using CSV, JSON, or HTML formats.
    Default: Current directory with timestamp.

.PARAMETER Limit
    Optional. Number of results per page (1-1000). Default: 1000

.EXAMPLE
    .\Get-S1AlertReport.ps1.ps1 -BaseURL "https://your-instance.sentinelone.net" -APIToken "YourAPIToken"
    
    Gets all suspicious and true positive threats from the past 30 days.

.EXAMPLE
    .\Get-S1AlertReport.ps1.ps1 -BaseURL "https://your-instance.sentinelone.net" -APIToken "YourAPIToken" -Days 7 -OutputFormat "CSV"
    
    Gets threats from the past 7 days and exports to CSV.

.EXAMPLE
    .\Get-S1AlertReport.ps1.ps1 -BaseURL "https://your-instance.sentinelone.net" -APIToken "YourAPIToken" -AnalystVerdicts @("true_positive") -OutputFormat "HTML"
    
    Gets only confirmed true positive threats from the past 30 days and generates an HTML report.

.EXAMPLE
    .\Get-S1AlertReport.ps1.ps1 -BaseURL "https://your-instance.sentinelone.net" -APIToken "YourAPIToken" -Days 90 -IncidentStatuses @("unresolved", "in_progress")
    
    Gets active (unresolved/in_progress) suspicious and true positive threats from the past 90 days.

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
    [int]$Days = 30,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("true_positive", "suspicious", "false_positive", "undefined")]
    [string[]]$AnalystVerdicts = @("true_positive", "suspicious"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$SiteIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AccountIds,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("malicious", "suspicious", "n/a")]
    [string[]]$ConfidenceLevels,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("unresolved", "in_progress", "resolved")]
    [string[]]$IncidentStatuses,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML", "All")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$Limit = 1000
)

# Ensure TLS 1.2 is used
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Calculate date range
$EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$StartDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

# Set default output path if not specified
if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location) "S1_Threats_$timestamp"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SentinelOne Threat Retrieval" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Date Range: Past $Days days" -ForegroundColor Yellow
Write-Host "Start Date: $StartDate" -ForegroundColor Yellow
Write-Host "End Date: $EndDate" -ForegroundColor Yellow
Write-Host "Analyst Verdicts: $($AnalystVerdicts -join ', ')" -ForegroundColor Yellow

# Prepare API headers
$headers = @{
    "Authorization" = "ApiToken $APIToken"
    "Content-Type" = "application/json"
}

# Initialize collections
$allThreats = @()
$cursor = $null
$pageCount = 1
$totalProcessed = 0

Write-Host "`nRetrieving threats from SentinelOne..." -ForegroundColor Yellow

try {
    # Loop through all pages of results
    do {
        # Build the URL with pagination and filters
        $threatsUrl = "$BaseURL/web/api/v2.1/threats?limit=$Limit"
        
        if ($cursor) {
            $threatsUrl += "&cursor=$cursor"
        }
        
        # Add date filters
        $threatsUrl += "&createdAt__gte=$StartDate"
        $threatsUrl += "&createdAt__lte=$EndDate"
        
        # Add optional filters
        if ($SiteIds) {
            $siteFilter = $SiteIds -join ","
            $threatsUrl += "&siteIds=$siteFilter"
        }
        
        if ($AccountIds) {
            $accountFilter = $AccountIds -join ","
            $threatsUrl += "&accountIds=$accountFilter"
        }
        
        if ($AnalystVerdicts) {
            $verdictFilter = $AnalystVerdicts -join ","
            $threatsUrl += "&analystVerdicts=$verdictFilter"
        }
        
        if ($ConfidenceLevels) {
            $confidenceFilter = $ConfidenceLevels -join ","
            $threatsUrl += "&confidenceLevels=$confidenceFilter"
        }
        
        if ($IncidentStatuses) {
            $incidentFilter = $IncidentStatuses -join ","
            $threatsUrl += "&incidentStatuses=$incidentFilter"
        }
        
        Write-Host "Retrieving page $pageCount..." -ForegroundColor Cyan
        $threatsResponse = Invoke-RestMethod -Uri $threatsUrl -Method GET -Headers $headers
        
        # Check if we have data
        if ($null -ne $threatsResponse.data -and $threatsResponse.data.Count -gt 0) {
            $pageThreats = $threatsResponse.data.Count
            Write-Host "  Found $pageThreats threats on page $pageCount" -ForegroundColor Green
            
            # Process each threat
            foreach ($threat in $threatsResponse.data) {
                $totalProcessed++
                
                # Extract MITRE ATT&CK tactics and techniques
                $tactics = @()
                $techniques = @()
                
                if ($threat.indicators -and $threat.indicators.Count -gt 0) {
                    foreach ($indicator in $threat.indicators) {
                        if ($indicator.tactics -and $indicator.tactics.Count -gt 0) {
                            foreach ($tactic in $indicator.tactics) {
                                if ($tactic.name) {
                                    $tactics += $tactic.name
                                }
                                if ($tactic.techniques -and $tactic.techniques.Count -gt 0) {
                                    foreach ($technique in $tactic.techniques) {
                                        if ($technique.name) {
                                            $techniques += $technique.name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Create threat object
                $threatObj = [PSCustomObject]@{
                    ThreatId = $threat.id
                    ThreatName = $threat.threatInfo.threatName
                    Classification = $threat.threatInfo.classification
                    ClassificationSource = $threat.threatInfo.classificationSource
                    ConfidenceLevel = $threat.threatInfo.confidenceLevel
                    AnalystVerdict = $threat.threatInfo.analystVerdict
                    IncidentStatus = $threat.threatInfo.incidentStatus
                    MitigationStatus = $threat.threatInfo.mitigationStatus
                    CreatedAt = $threat.threatInfo.createdAt
                    UpdatedAt = $threat.threatInfo.updatedAt
                    AgentId = $threat.agentRealtimeInfo.agentId
                    AgentComputerName = $threat.agentRealtimeInfo.agentComputerName
                    AgentDomain = $threat.agentRealtimeInfo.agentDomain
                    AgentOsType = $threat.agentRealtimeInfo.agentOsType
                    AgentVersion = $threat.agentRealtimeInfo.agentVersion
                    SiteId = $threat.agentRealtimeInfo.siteId
                    SiteName = $threat.agentRealtimeInfo.siteName
                    AccountId = $threat.agentRealtimeInfo.accountId
                    AccountName = $threat.agentRealtimeInfo.accountName
                    FilePath = $threat.threatInfo.filePath
                    FileExtension = $threat.threatInfo.fileExtensionType
                    SHA1 = $threat.threatInfo.sha1
                    SHA256 = $threat.threatInfo.sha256
                    InitiatedBy = $threat.threatInfo.initiatedBy
                    InitiatedByDescription = $threat.threatInfo.initiatedByDescription
                    OriginatorProcess = $threat.threatInfo.originatorProcess
                    ProcessUser = $threat.threatInfo.processUser
                    MitreTactics = (($tactics | Select-Object -Unique) -join "; ")
                    MitreTechniques = (($techniques | Select-Object -Unique) -join "; ")
                    DetectionEngines = ($threat.threatInfo.engines -join "; ")
                    FailedActions = $threat.threatInfo.failedActions
                    PendingActions = $threat.threatInfo.pendingActions
                    RebootRequired = $threat.threatInfo.rebootRequired
                }
                
                $allThreats += $threatObj
            }
            
            # Get next cursor for pagination
            $cursor = $threatsResponse.pagination.nextCursor
            $pageCount++
            
        } else {
            Write-Host "  No threats found on page $pageCount" -ForegroundColor Yellow
            break
        }
        
    } while ($cursor)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Total Threats Retrieved: $totalProcessed" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    if ($totalProcessed -eq 0) {
        Write-Host "No threats found matching the specified criteria." -ForegroundColor Yellow
        return
    }
    
    # Display summary statistics
    Write-Host "`nTHREAT SUMMARY:" -ForegroundColor Cyan
    
    # By Analyst Verdict
    $verdictStats = $allThreats | Group-Object AnalystVerdict | 
        Select-Object @{Name="Analyst Verdict"; Expression={$_.Name}}, Count, 
                      @{Name="Percentage"; Expression={[math]::Round(($_.Count / $totalProcessed) * 100, 2)}}
    Write-Host "`nBy Analyst Verdict:" -ForegroundColor Yellow
    $verdictStats | Format-Table -AutoSize
    
    # By Incident Status
    $incidentStats = $allThreats | Group-Object IncidentStatus | 
        Select-Object @{Name="Incident Status"; Expression={$_.Name}}, Count, 
                      @{Name="Percentage"; Expression={[math]::Round(($_.Count / $totalProcessed) * 100, 2)}}
    Write-Host "By Incident Status:" -ForegroundColor Yellow
    $incidentStats | Format-Table -AutoSize
    
    # By Confidence Level
    $confidenceStats = $allThreats | Group-Object ConfidenceLevel | 
        Select-Object @{Name="Confidence Level"; Expression={$_.Name}}, Count, 
                      @{Name="Percentage"; Expression={[math]::Round(($_.Count / $totalProcessed) * 100, 2)}}
    Write-Host "By Confidence Level:" -ForegroundColor Yellow
    $confidenceStats | Format-Table -AutoSize
    
    # Top Sites
    $siteStats = $allThreats | Group-Object SiteName | 
        Sort-Object Count -Descending | 
        Select-Object @{Name="Site Name"; Expression={$_.Name}}, Count -First 10
    Write-Host "Top 10 Sites by Threat Count:" -ForegroundColor Yellow
    $siteStats | Format-Table -AutoSize
    
    # Top Endpoints
    $endpointStats = $allThreats | Group-Object AgentComputerName | 
        Sort-Object Count -Descending | 
        Select-Object @{Name="Computer Name"; Expression={$_.Name}}, Count -First 10
    Write-Host "Top 10 Endpoints by Threat Count:" -ForegroundColor Yellow
    $endpointStats | Format-Table -AutoSize
    
    # Export results based on OutputFormat
    if ($OutputFormat -in @("Console", "All")) {
        Write-Host "`nTHREAT DETAILS (First 20):" -ForegroundColor Cyan
        $allThreats | Select-Object -First 20 | 
            Select-Object ThreatId, ThreatName, AnalystVerdict, IncidentStatus, AgentComputerName, SiteName, CreatedAt | 
            Format-Table -AutoSize
    }
    
    if ($OutputFormat -in @("CSV", "All")) {
        Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
        $csvFile = "${OutputPath}.csv"
        $allThreats | Export-Csv -Path $csvFile -NoTypeInformation
        Write-Host "  CSV exported to: $csvFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("JSON", "All")) {
        Write-Host "`nExporting to JSON..." -ForegroundColor Yellow
        
        $jsonData = @{
            Summary = @{
                DateRange = @{
                    Start = $StartDate
                    End = $EndDate
                    Days = $Days
                }
                TotalThreats = $totalProcessed
                AnalystVerdicts = $AnalystVerdicts
            }
            Statistics = @{
                ByVerdict = $verdictStats
                ByIncidentStatus = $incidentStats
                ByConfidenceLevel = $confidenceStats
                TopSites = $siteStats
                TopEndpoints = $endpointStats
            }
            Threats = $allThreats
        }
        
        $jsonFile = "${OutputPath}.json"
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Host "  JSON exported to: $jsonFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("HTML", "All")) {
        Write-Host "`nExporting to HTML..." -ForegroundColor Yellow
        
        # Build HTML content
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>SentinelOne Threat Report</title>
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
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128737;&#65039; SentinelOne Threat Report</h1>
        <div class="subtitle">Date Range: Past $Days days ($StartDate to $EndDate)</div>
        <div class="subtitle">Analyst Verdicts: $($AnalystVerdicts -join ', ')</div>
        <div class="subtitle">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value">$totalProcessed</div>
                <div class="label">Total Threats</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>By Analyst Verdict</h2>
        <table>
            <thead>
                <tr>
                    <th>Analyst Verdict</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $verdictStats) {
            $htmlContent += "<tr><td>$($stat.'Analyst Verdict')</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>By Incident Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Incident Status</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $incidentStats) {
            $htmlContent += "<tr><td>$($stat.'Incident Status')</td><td>$($stat.Count)</td><td>$($stat.Percentage)%</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Top 10 Sites by Threat Count</h2>
        <table>
            <thead>
                <tr>
                    <th>Site Name</th>
                    <th>Threat Count</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $siteStats) {
            $htmlContent += "<tr><td>$($stat.'Site Name')</td><td>$($stat.Count)</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>All Threats</h2>
        <table>
            <thead>
                <tr>
                    <th>Threat Name</th>
                    <th>Verdict</th>
                    <th>Status</th>
                    <th>Computer</th>
                    <th>Site</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($threat in $allThreats) {
            $htmlContent += "<tr><td>$($threat.ThreatName)</td><td>$($threat.AnalystVerdict)</td><td>$($threat.IncidentStatus)</td><td>$($threat.AgentComputerName)</td><td>$($threat.SiteName)</td><td>$($threat.CreatedAt)</td></tr>`n"
        }
        
        $currentYear = (Get-Date).Year
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>Report generated by SentinelOne Threat Retrieval Script</p>
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
    
    # Return the threats for pipeline usage
    return $allThreats
    
} catch {
    Write-Host "`nError occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
