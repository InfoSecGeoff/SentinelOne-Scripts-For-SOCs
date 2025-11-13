<#
.SYNOPSIS
    Get MITRE ATT&CK Tactics, Techniques, and Procedures (TTP) distribution from SentinelOne threats/alerts.

.DESCRIPTION
    This script retrieves all threats from SentinelOne and analyzes the distribution of MITRE ATT&CK 
    tactics and techniques across the environment. It provides comprehensive statistics and can filter
    by date range, analyst verdicts, and other criteria. The script handles pagination automatically 
    and provides progress updates.
    
    By default, the script filters for threats marked as "true_positive" or "suspicious" to focus on 
    genuine threats rather than false positives.

.PARAMETER BaseURL
    The base URL of your SentinelOne console (e.g., "https://usea1-swprd1.sentinelone.net")

.PARAMETER APIToken
    Your SentinelOne API token

.PARAMETER StartDate
    Optional. Filter threats created on or after this date. Format: "yyyy-MM-ddTHH:mm:ss.fffZ"
    If not specified, defaults to 1 year ago.

.PARAMETER EndDate
    Optional. Filter threats created on or before this date. Format: "yyyy-MM-ddTHH:mm:ss.fffZ"
    If not specified, defaults to current date/time.

.PARAMETER SiteIds
    Optional. Array of Site IDs to filter by.

.PARAMETER AccountIds
    Optional. Array of Account IDs to filter by.

.PARAMETER AnalystVerdicts
    Optional. Array of analyst verdicts to filter by. Valid values: "true_positive", "suspicious", "false_positive", "undefined"
    Default: "true_positive", "suspicious" (excludes false positives by default)

.PARAMETER ConfidenceLevels
    Optional. Array of confidence levels to filter by. Valid values: "malicious", "suspicious", "n/a"

.PARAMETER IncidentStatuses
    Optional. Array of incident statuses to filter by. Valid values: "unresolved", "in_progress", "resolved"
    Default: "unresolved", "in_progress"

.PARAMETER OutputFormat
    Optional. Output format: "Console", "CSV", "JSON", "HTML", or "All". Default: "Console"

.PARAMETER OutputPath
    Optional. Path for output files when using CSV, JSON, or HTML formats.
    Default: Current directory with timestamp.

.PARAMETER Limit
    Optional. Number of results per page (1-1000). Default: 1000

.PARAMETER ShowEmptyThreats
    Optional. Include threats that have no MITRE ATT&CK data in the statistics. Default: $false

.EXAMPLE
    Get-S1IncidentMITREMapping.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken"
    
    Gets MITRE ATT&CK distribution for all threats from the past year that are marked as true_positive or suspicious (default).

.EXAMPLE
    Get-S1IncidentMITREMapping.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -StartDate "2024-01-01T00:00:00.000Z" -EndDate "2024-12-31T23:59:59.999Z" -OutputFormat "All"
    
    Gets distribution for 2024 (true positives and suspicious only) and exports to all formats.

.EXAMPLE
    Get-S1IncidentMITREMapping.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -AnalystVerdicts @("true_positive") -OutputFormat "CSV"
    
    Gets distribution for only confirmed true positive threats and exports to CSV.

.EXAMPLE
    Get-S1IncidentMITREMapping.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -AnalystVerdicts @("true_positive", "suspicious", "false_positive", "undefined")
    
    Gets distribution for ALL threats regardless of analyst verdict.

.EXAMPLE
    Get-S1IncidentMITREMapping.ps1 -BaseURL "https://usea1-swprd1.sentinelone.net" -APIToken "YourAPIToken" -AnalystVerdicts @("false_positive") -OutputFormat "HTML"
    
    Analyzes MITRE TTPs from false positive threats to understand what techniques trigger false alerts.

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    Requires: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$BaseURL,
    
    [Parameter(Mandatory=$true)]
    [string]$APIToken,
    
    [Parameter(Mandatory=$false)]
    [string]$StartDate,
    
    [Parameter(Mandatory=$false)]
    [string]$EndDate,
    
    [Parameter(Mandatory=$false)]
    [string[]]$SiteIds,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AccountIds,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("true_positive", "suspicious", "false_positive", "undefined")]
    [string[]]$AnalystVerdicts = @("true_positive", "suspicious"),
    
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
    [int]$Limit = 1000,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowEmptyThreats
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $StartDate) {
    $StartDate = (Get-Date).AddYears(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}
if (-not $EndDate) {
    $EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path (Get-Location) "S1_MITRE_Distribution_$timestamp"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SentinelOne MITRE ATT&CK Distribution" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Date Range: $StartDate to $EndDate" -ForegroundColor Yellow
Write-Host "Analyst Verdicts: $($AnalystVerdicts -join ', ')" -ForegroundColor Yellow

$headers = @{
    "Authorization" = "ApiToken $APIToken"
    "Content-Type" = "application/json"
}

# Start collection
$allThreats = @()
$tacticsDistribution = @{}
$techniquesDistribution = @{}
$tacticTechniqueMapping = @{}
$threatsMitreData = @()
$cursor = $null
$pageCount = 1
$totalProcessed = 0
$threatsWithMitre = 0
$threatsWithoutMitre = 0

Write-Host "`nRetrieving threats from SentinelOne..." -ForegroundColor Yellow

try {
    do {
        $threatsUrl = "$BaseURL/web/api/v2.1/threats?limit=$Limit"
        
        if ($cursor) {
            $threatsUrl += "&cursor=$cursor"
        }
    

        $threatsUrl += "&createdAt__gte=$StartDate"
        $threatsUrl += "&createdAt__lte=$EndDate"

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

        if ($null -ne $threatsResponse.data -and $threatsResponse.data.Count -gt 0) {
            $pageThreats = $threatsResponse.data.Count
            Write-Host "  Found $pageThreats threats on page $pageCount" -ForegroundColor Green

            foreach ($threat in $threatsResponse.data) {
                $totalProcessed++

                $hasMitreData = $false
                $threatTactics = @()
                $threatTechniques = @()
                #Process tactics
                if ($threat.indicators -and $threat.indicators.Count -gt 0) {
                    foreach ($indicator in $threat.indicators) {
                        if ($indicator.tactics -and $indicator.tactics.Count -gt 0) {
                            $hasMitreData = $true
                            
                            foreach ($tactic in $indicator.tactics) {
                                $tacticName = $tactic.name
                                
                                if ($tacticName) {
                                    # Count tactics
                                    if (-not $tacticsDistribution.ContainsKey($tacticName)) {
                                        $tacticsDistribution[$tacticName] = 0
                                    }
                                    $tacticsDistribution[$tacticName]++
                                    $threatTactics += $tacticName
                                    
                                    # Process techniques
                                    if ($tactic.techniques -and $tactic.techniques.Count -gt 0) {
                                        foreach ($technique in $tactic.techniques) {
                                            $techniqueName = $technique.name
                                            $techniqueLink = $technique.link
                                            
                                            if ($techniqueName) {
                                                # Count techniques
                                                if (-not $techniquesDistribution.ContainsKey($techniqueName)) {
                                                    $techniquesDistribution[$techniqueName] = @{
                                                        Count = 0
                                                        Link = $techniqueLink
                                                    }
                                                }
                                                $techniquesDistribution[$techniqueName].Count++
                                                $threatTechniques += $techniqueName
                                                
                                                # Map tactic to techniques
                                                if (-not $tacticTechniqueMapping.ContainsKey($tacticName)) {
                                                    $tacticTechniqueMapping[$tacticName] = @{}
                                                }
                                                if (-not $tacticTechniqueMapping[$tacticName].ContainsKey($techniqueName)) {
                                                    $tacticTechniqueMapping[$tacticName][$techniqueName] = 0
                                                }
                                                $tacticTechniqueMapping[$tacticName][$techniqueName]++
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if ($hasMitreData) {
                    $threatsWithMitre++
                } else {
                    $threatsWithoutMitre++
                }
                
                $threatsMitreData += [PSCustomObject]@{
                    ThreatId = $threat.id
                    ThreatName = $threat.threatInfo.threatName
                    Classification = $threat.threatInfo.classification
                    ConfidenceLevel = $threat.threatInfo.confidenceLevel
                    AnalystVerdict = $threat.threatInfo.analystVerdict
                    CreatedAt = $threat.threatInfo.createdAt
                    AgentComputerName = $threat.agentRealtimeInfo.agentComputerName
                    SiteName = $threat.agentRealtimeInfo.siteName
                    HasMitreData = $hasMitreData
                    Tactics = ($threatTactics | Select-Object -Unique) -join "; "
                    Techniques = ($threatTechniques | Select-Object -Unique) -join "; "
                }
            }

            $cursor = $threatsResponse.pagination.nextCursor
            $pageCount++
            
        } else {
            Write-Host "  No threats found on page $pageCount" -ForegroundColor Yellow
            break
        }
        
    } while ($cursor)
    
    Write-Host "`nTotal Threats Processed: $totalProcessed" -ForegroundColor Green
    Write-Host "  Threats with MITRE Data: $threatsWithMitre" -ForegroundColor Green
    Write-Host "  Threats without MITRE Data: $threatsWithoutMitre" -ForegroundColor Yellow
    
    # Calculate stats
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "MITRE ATT&CK TACTICS DISTRIBUTION" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Count unique threats per tactic (not total occurrences)
    $tacticThreatCounts = @{}
    foreach ($threat in $threatsMitreData | Where-Object { $_.HasMitreData }) {
        $uniqueTactics = ($threat.Tactics -split "; " | Select-Object -Unique)
        foreach ($tactic in $uniqueTactics) {
            if ($tactic) {
                if (-not $tacticThreatCounts.ContainsKey($tactic)) {
                    $tacticThreatCounts[$tactic] = @{}
                }
                $tacticThreatCounts[$tactic][$threat.ThreatId] = $true
            }
        }
    }
    
    $tacticsStats = $tacticThreatCounts.GetEnumerator() | 
        Sort-Object {$_.Value.Count} -Descending | 
        Select-Object @{Name="Tactic"; Expression={$_.Key}},
                      @{Name="Occurrences"; Expression={$tacticsDistribution[$_.Key]}},
                      @{Name="Threats"; Expression={$_.Value.Count}},
                      @{Name="% of Threats"; Expression={[math]::Round(($_.Value.Count / $threatsWithMitre) * 100, 2)}}
    
    if ($tacticsStats) {
        $tacticsStats | Format-Table -AutoSize
    } else {
        Write-Host "No MITRE tactics data found." -ForegroundColor Yellow
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "MITRE ATT&CK TECHNIQUES DISTRIBUTION" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Count unique threats per technique (not total occurrences)
    $techniqueThreatCounts = @{}
    foreach ($threat in $threatsMitreData | Where-Object { $_.HasMitreData }) {
        $uniqueTechniques = ($threat.Techniques -split "; " | Select-Object -Unique)
        foreach ($technique in $uniqueTechniques) {
            if ($technique) {
                if (-not $techniqueThreatCounts.ContainsKey($technique)) {
                    $techniqueThreatCounts[$technique] = @{}
                }
                $techniqueThreatCounts[$technique][$threat.ThreatId] = $true
            }
        }
    }
    
    $techniquesStats = $techniqueThreatCounts.GetEnumerator() | 
        Sort-Object {$_.Value.Count} -Descending | 
        Select-Object @{Name="Technique"; Expression={$_.Key}},
                      @{Name="Occurrences"; Expression={$techniquesDistribution[$_.Key].Count}},
                      @{Name="Threats"; Expression={$_.Value.Count}},
                      @{Name="% of Threats"; Expression={[math]::Round(($_.Value.Count / $threatsWithMitre) * 100, 2)}},
                      @{Name="Link"; Expression={$techniquesDistribution[$_.Key].Link}}
    
    if ($techniquesStats) {
        $techniquesStats | Select-Object -First 20 | Format-Table -AutoSize
        
        if ($techniquesStats.Count -gt 20) {
            Write-Host "Showing top 20 techniques. Total unique techniques: $($techniquesStats.Count)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No MITRE techniques data found." -ForegroundColor Yellow
    }
    
    # Export results based on OutputFormat
    if ($OutputFormat -in @("CSV", "All")) {
        Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
        
        # Export tactics
        $tacticsFile = "${OutputPath}_Tactics.csv"
        $tacticsStats | Export-Csv -Path $tacticsFile -NoTypeInformation
        Write-Host "  Tactics exported to: $tacticsFile" -ForegroundColor Green
        
        # Export techniques
        $techniquesFile = "${OutputPath}_Techniques.csv"
        $techniquesStats | Export-Csv -Path $techniquesFile -NoTypeInformation
        Write-Host "  Techniques exported to: $techniquesFile" -ForegroundColor Green
        
        # Export threat details
        if ($ShowEmptyThreats) {
            $threatDetailsFile = "${OutputPath}_ThreatDetails.csv"
            $threatsMitreData | Export-Csv -Path $threatDetailsFile -NoTypeInformation
        } else {
            $threatDetailsFile = "${OutputPath}_ThreatDetails.csv"
            $threatsMitreData | Where-Object { $_.HasMitreData } | Export-Csv -Path $threatDetailsFile -NoTypeInformation
        }
        Write-Host "  Threat details exported to: $threatDetailsFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("JSON", "All")) {
        Write-Host "`nExporting to JSON..." -ForegroundColor Yellow
        
        $jsonData = @{
            Summary = @{
                DateRange = @{
                    Start = $StartDate
                    End = $EndDate
                }
                TotalThreats = $totalProcessed
                ThreatsWithMitre = $threatsWithMitre
                ThreatsWithoutMitre = $threatsWithoutMitre
            }
            Tactics = $tacticsStats
            Techniques = $techniquesStats
            TacticTechniqueMapping = $tacticTechniqueMapping
            ThreatDetails = if ($ShowEmptyThreats) { $threatsMitreData } else { $threatsMitreData | Where-Object { $_.HasMitreData } }
        }
        
        $jsonFile = "${OutputPath}.json"
        $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Host "  JSON exported to: $jsonFile" -ForegroundColor Green
    }
    
    if ($OutputFormat -in @("HTML", "All")) {
        Write-Host "`nExporting to HTML..." -ForegroundColor Yellow
        
        # Build HTML report
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>SentinelOne MITRE ATT&CK Distribution Report</title>
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
        .link { color: #667eea; text-decoration: none; }
        .link:hover { text-decoration: underline; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128737;&#65039; SentinelOne MITRE ATT&amp;CK Distribution Report</h1>
        <div class="subtitle">Date Range: $StartDate to $EndDate</div>
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
            <div class="summary-item">
                <div class="value">$threatsWithMitre</div>
                <div class="label">Threats with MITRE Data</div>
            </div>
            <div class="summary-item">
                <div class="value">$threatsWithoutMitre</div>
                <div class="label">Threats without MITRE Data</div>
            </div>
            <div class="summary-item">
                <div class="value">$($tacticsDistribution.Count)</div>
                <div class="label">Unique Tactics</div>
            </div>
            <div class="summary-item">
                <div class="value">$($techniquesDistribution.Count)</div>
                <div class="label">Unique Techniques</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>&#128202; MITRE ATT&amp;CK Tactics Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Tactic</th>
                    <th>Total Occurrences</th>
                    <th>Unique Threats</th>
                    <th>% of Threats</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in $tacticsStats) {
            $htmlContent += "<tr><td>$($stat.Tactic)</td><td>$($stat.Occurrences)</td><td>$($stat.Threats)</td><td>$($stat.'% of Threats')%</td></tr>`n"
        }
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>&#127919; MITRE ATT&amp;CK Techniques Distribution (Top 50)</h2>
        <table>
            <thead>
                <tr>
                    <th>Technique</th>
                    <th>Total Occurrences</th>
                    <th>Unique Threats</th>
                    <th>% of Threats</th>
                    <th>Link</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($stat in ($techniquesStats | Select-Object -First 50)) {
            $linkHtml = if ($stat.Link) { "<a href='$($stat.Link)' target='_blank' class='link'>&#128279; View</a>" } else { "N/A" }
            $htmlContent += "<tr><td>$($stat.Technique)</td><td>$($stat.Occurrences)</td><td>$($stat.Threats)</td><td>$($stat.'% of Threats')%</td><td>$linkHtml</td></tr>`n"
        }
        
        $currentYear = (Get-Date).Year
        
        $htmlContent += @"
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>Report generated by SentinelOne MITRE ATT&amp;CK Distribution Script</p>
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
    
} catch {
    Write-Host "`nError occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
