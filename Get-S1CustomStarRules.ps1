<#
.SYNOPSIS
    Identifies all custom STAR (Custom Detection) rules organized by client/account/site.

.DESCRIPTION
    This script queries the SentinelOne Cloud Detection API to retrieve all custom
    detection rules (STAR rules) and organizes them by scope (Global, Account, Site, Group).
    
    Custom detection rules are client-specific threat detection rules that supplement
    SentinelOne's built-in threat intelligence. This script helps identify which clients
    have custom rules and what they're monitoring for.

.PARAMETER S1Url
    The URL of your SentinelOne management console

.PARAMETER S1ApiKey
    The API key for authenticating to SentinelOne

.PARAMETER AccountIds
    Optional. Filter by specific Account IDs (comma-separated)

.PARAMETER SiteIds
    Optional. Filter by specific Site IDs (comma-separated)

.PARAMETER Status
    Optional. Filter by status: Enabled, Disabled, Deleted
    Default: All statuses

.PARAMETER IncludeGlobal
    Optional. Include Global scope rules in the output
    Default: $false (only show Account/Site/Group custom rules)

.PARAMETER OutputFormat
    The output format for results. Options: Console, CSV, JSON, HTML
    Default: Console

.PARAMETER OutputPath
    The file path for output when using CSV, JSON, or HTML formats

.EXAMPLE
    .\Get-S1CustomSTARRules.ps1 -S1Url "https://your-tenant.sentinelone.net" -S1ApiKey "your-api-key"
    
    Lists all custom STAR rules organized by client.

.EXAMPLE
    .\Get-S1CustomSTARRules.ps1 -S1Url "https://your-tenant.sentinelone.net" -S1ApiKey "your-api-key" -IncludeGlobal -OutputFormat HTML
    
    Generates an HTML report including global rules.

.EXAMPLE
    .\Get-S1CustomSTARRules.ps1 -S1Url "https://your-tenant.sentinelone.net" -S1ApiKey "your-api-key" -Status "Enabled" -OutputFormat CSV
    
    Exports only enabled rules to CSV.

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$S1Url,
    
    [Parameter(Mandatory = $true)]
    [string]$S1ApiKey,
    
    [Parameter(Mandatory = $false)]
    [string]$AccountIds,
    
    [Parameter(Mandatory = $false)]
    [string]$SiteIds,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Enabled", "Disabled", "Deleted")]
    [string]$Status = "All",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeGlobal,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "JSON", "HTML")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

$rulesApiUrl = "$S1Url/web/api/v2.1/cloud-detection/rules"

function Invoke-S1ApiCall {
    param([string]$Url)
    
    $headers = @{
        "Authorization" = "ApiToken $S1ApiKey"
        "Content-Type"  = "application/json"
    }
    
    try {
        return Invoke-RestMethod -Uri $Url -Method GET -Headers $headers
    }
    catch {
        Write-Warning "API call failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-S1CustomRules {
    param([hashtable]$QueryParams = @{})
    
    $allRules = @()
    $cursor = $null
    $limit = 1000
    
    do {
        $queryString = "?limit=$limit"
        
        foreach ($key in $QueryParams.Keys) {
            if ($QueryParams[$key]) {
                $queryString += "&$key=$($QueryParams[$key])"
            }
        }
        
        if ($cursor) {
            $queryString += "&cursor=$cursor"
        }
        
        $url = "$rulesApiUrl$queryString"
        Write-Verbose "Fetching: $url"
        
        $response = Invoke-S1ApiCall -Url $url
        
        if ($response -and $response.data) {
            $allRules += $response.data
            Write-Verbose "Retrieved $($response.data.Count) rules. Total: $($allRules.Count)"
        }
        
        $cursor = if ($response.pagination.nextCursor) { $response.pagination.nextCursor } else { $null }
    } while ($cursor)
    
    return $allRules
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "S1 Custom STAR Rules Report" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  SentinelOne URL: $S1Url"
Write-Host "  Status Filter: $Status"
Write-Host "  Include Global Rules: $IncludeGlobal"
Write-Host ""

$queryParams = @{}
if ($AccountIds) { $queryParams['accountIds'] = $AccountIds }
if ($SiteIds) { $queryParams['siteIds'] = $SiteIds }
if ($Status -ne "All") { $queryParams['statuses'] = $Status }

Write-Host "Retrieving custom detection rules..." -ForegroundColor Green
$startTime = Get-Date

$allRules = Get-S1CustomRules -QueryParams $queryParams

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "  Total rules retrieved: $($allRules.Count)" -ForegroundColor Cyan
Write-Host "  Completed in $($duration.TotalSeconds.ToString('F2')) seconds`n" -ForegroundColor Green

if ($allRules.Count -eq 0) {
    Write-Host "No custom detection rules found." -ForegroundColor Yellow
    return
}

# Filter for global rule exclusion
if (-not $IncludeGlobal) {
    $filteredCount = ($allRules | Where-Object { $_.scope -eq "Global" }).Count
    $allRules = $allRules | Where-Object { $_.scope -ne "Global" }
    if ($filteredCount -gt 0) {
        Write-Host "  Excluded $filteredCount Global scope rules (use -IncludeGlobal to include them)" -ForegroundColor Yellow
        Write-Host "  Client-specific rules: $($allRules.Count)`n" -ForegroundColor Cyan
    }
}

# Process results
$results = @()
foreach ($rule in $allRules) {
    $results += [PSCustomObject]@{
        Scope              = $rule.scope
        AccountName        = if ($rule.accountName) { $rule.accountName } else { "N/A" }
        SiteName           = if ($rule.siteName) { $rule.siteName } else { "N/A" }
        RuleName           = $rule.name
        Description        = if ($rule.description) { $rule.description } else { "N/A" }
        Status             = $rule.status
        Severity           = $rule.severity
        Creator            = $rule.creator
        CreatedDate        = if ($rule.createdAt) { ([DateTime]$rule.createdAt).ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
        UpdatedDate        = if ($rule.updatedAt) { ([DateTime]$rule.updatedAt).ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
        AlertsGenerated    = $rule.generatedAlerts
        LastAlertTime      = if ($rule.lastAlertTime) { ([DateTime]$rule.lastAlertTime).ToString("yyyy-MM-dd HH:mm") } else { "Never" }
        TreatAsThreat      = $rule.treatAsThreat
        NetworkQuarantine  = $rule.networkQuarantine
        QueryLanguage      = $rule.queryLang
        Query              = $rule.s1ql
        Expired            = $rule.expired
        ReachedLimit       = $rule.reachedLimit
        RuleId             = $rule.id
        ScopeId            = if ($rule.scopeId) { $rule.scopeId } else { "N/A" }
    }
}

switch ($OutputFormat) {
    "Console" {
        $byScope = $results | Group-Object Scope | Sort-Object Name
        
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Custom STAR Rules by Client" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        foreach ($scopeGroup in $byScope) {
            Write-Host "`n=== $($scopeGroup.Name) Scope ($($scopeGroup.Count) rules) ===" -ForegroundColor Yellow
            
            if ($scopeGroup.Name -eq "Account") {
                $byAccount = $scopeGroup.Group | Group-Object AccountName | Sort-Object Name
                foreach ($account in $byAccount) {
                    Write-Host "`n  Account: $($account.Name) ($($account.Count) rules)" -ForegroundColor Cyan
                    Write-Host "  " + ("-" * 78) -ForegroundColor Cyan
                    
                    $account.Group | Sort-Object CreatedDate -Descending | 
                        Format-Table -Property RuleName, Status, Severity, Creator, AlertsGenerated, CreatedDate -AutoSize |
                        Out-String | ForEach-Object { "  " + $_ }
                }
            }
            elseif ($scopeGroup.Name -eq "Site") {
                $bySite = $scopeGroup.Group | Group-Object AccountName, SiteName | Sort-Object Name
                foreach ($site in $bySite) {
                    $names = $site.Name -split ', '
                    Write-Host "`n  Account: $($names[0]) | Site: $($names[1]) ($($site.Count) rules)" -ForegroundColor Cyan
                    Write-Host "  " + ("-" * 78) -ForegroundColor Cyan
                    
                    $site.Group | Sort-Object CreatedDate -Descending | 
                        Format-Table -Property RuleName, Status, Severity, Creator, AlertsGenerated, CreatedDate -AutoSize |
                        Out-String | ForEach-Object { "  " + $_ }
                }
            }
            else {
                Write-Host ""
                $scopeGroup.Group | Sort-Object CreatedDate -Descending | 
                    Format-Table -Property RuleName, Status, Severity, Creator, AlertsGenerated, CreatedDate, AccountName, SiteName -AutoSize
            }
        }
        
        # Statistics
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Summary Statistics" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        $enabledCount = ($results | Where-Object { $_.Status -eq "Enabled" }).Count
        $disabledCount = ($results | Where-Object { $_.Status -eq "Disabled" }).Count
        $totalAlerts = ($results | Measure-Object -Property AlertsGenerated -Sum).Sum
        
        Write-Host "Total Custom Rules: $($results.Count)"
        Write-Host "  Enabled: $enabledCount"
        Write-Host "  Disabled: $disabledCount"
        Write-Host "Total Alerts Generated: $totalAlerts"
        Write-Host "`nRules by Scope:"
        $results | Group-Object Scope | Sort-Object Name | Format-Table Name, Count -AutoSize
        
        Write-Host "Top Alert Generators:" -ForegroundColor Yellow
        $results | Where-Object { $_.AlertsGenerated -gt 0 } | 
            Sort-Object AlertsGenerated -Descending | 
            Select-Object -First 10 | 
            Format-Table RuleName, AccountName, SiteName, AlertsGenerated, LastAlertTime -AutoSize
    }
    
    "CSV" {
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = ".\S1_Custom_STAR_Rules_$timestamp.csv"
        }
        
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
        Write-Host "Total records: $($results.Count)" -ForegroundColor Cyan
    }
    
    "JSON" {
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = ".\S1_Custom_STAR_Rules_$timestamp.json"
        }
        
        $output = @{
            GeneratedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TotalRules    = $results.Count
            EnabledRules  = ($results | Where-Object { $_.Status -eq "Enabled" }).Count
            TotalAlerts   = ($results | Measure-Object -Property AlertsGenerated -Sum).Sum
            Rules         = $results
        }
        
        $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
    }
    
    "HTML" {
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OutputPath = ".\S1_Custom_STAR_Rules_$timestamp.html"
        }
        
        Add-Type -AssemblyName System.Web
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Custom STAR Rules Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat { display: inline-block; margin-right: 30px; margin-bottom: 10px; }
        .stat-label { font-weight: bold; color: #666; }
        .stat-value { font-size: 24px; color: #667eea; font-weight: bold; }
        .scope-section { background-color: white; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .scope-header { background-color: #667eea; color: white; padding: 10px; border-radius: 3px; margin-bottom: 10px; font-weight: bold; }
        .client-header { background-color: #764ba2; color: white; padding: 8px; border-radius: 3px; margin-top: 15px; margin-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background-color: #764ba2; color: white; padding: 10px; text-align: left; font-size: 12px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; font-size: 12px; }
        tr:hover { background-color: #f5f5f5; }
        .status-enabled { color: green; font-weight: bold; }
        .status-disabled { color: orange; font-weight: bold; }
        .severity-high { color: red; font-weight: bold; }
        .severity-medium { color: orange; font-weight: bold; }
        .severity-low { color: blue; }
        .query-cell { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 11px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Custom STAR Rules Report</h1>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
    
    <div class="summary">
        <h3>Summary</h3>
        <div class="stat">
            <div class="stat-label">Total Rules</div>
            <div class="stat-value">$($results.Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Enabled</div>
            <div class="stat-value">$(($results | Where-Object { $_.Status -eq 'Enabled' }).Count)</div>
        </div>
        <div class="stat">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-value">$(($results | Measure-Object -Property AlertsGenerated -Sum).Sum)</div>
        </div>
    </div>
"@
        
        $byScope = $results | Group-Object Scope | Sort-Object Name
        
        foreach ($scopeGroup in $byScope) {
            $html += "<div class='scope-section'>`n<div class='scope-header'>$($scopeGroup.Name) Scope - $($scopeGroup.Count) Rules</div>`n"
            
            if ($scopeGroup.Name -eq "Account") {
                $byAccount = $scopeGroup.Group | Group-Object AccountName | Sort-Object Name
                foreach ($account in $byAccount) {
                    $html += "<div class='client-header'>Account: $($account.Name) - $($account.Count) Rules</div>`n"
                    $html += "<table><tr><th>Rule Name</th><th>Status</th><th>Severity</th><th>Creator</th><th>Alerts</th><th>Created</th><th>Query</th></tr>`n"
                    
                    foreach ($rule in ($account.Group | Sort-Object CreatedDate -Descending)) {
                        $statusClass = if ($rule.Status -eq "Enabled") { "status-enabled" } else { "status-disabled" }
                        $severityClass = "severity-" + $rule.Severity.ToLower()
                        $html += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.RuleName))</td>"
                        $html += "<td class='$statusClass'>$($rule.Status)</td>"
                        $html += "<td class='$severityClass'>$($rule.Severity)</td>"
                        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($rule.Creator))</td>"
                        $html += "<td>$($rule.AlertsGenerated)</td>"
                        $html += "<td>$($rule.CreatedDate)</td>"
                        $html += "<td class='query-cell' title='$([System.Web.HttpUtility]::HtmlEncode($rule.Query))'>$([System.Web.HttpUtility]::HtmlEncode($rule.Query))</td></tr>`n"
                    }
                    $html += "</table>`n"
                }
            }
            elseif ($scopeGroup.Name -eq "Site") {
                $bySite = $scopeGroup.Group | Group-Object AccountName, SiteName | Sort-Object Name
                foreach ($site in $bySite) {
                    $names = $site.Name -split ', '
                    $html += "<div class='client-header'>Account: $($names[0]) | Site: $($names[1]) - $($site.Count) Rules</div>`n"
                    $html += "<table><tr><th>Rule Name</th><th>Status</th><th>Severity</th><th>Creator</th><th>Alerts</th><th>Created</th><th>Query</th></tr>`n"
                    
                    foreach ($rule in ($site.Group | Sort-Object CreatedDate -Descending)) {
                        $statusClass = if ($rule.Status -eq "Enabled") { "status-enabled" } else { "status-disabled" }
                        $severityClass = "severity-" + $rule.Severity.ToLower()
                        $html += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.RuleName))</td>"
                        $html += "<td class='$statusClass'>$($rule.Status)</td>"
                        $html += "<td class='$severityClass'>$($rule.Severity)</td>"
                        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($rule.Creator))</td>"
                        $html += "<td>$($rule.AlertsGenerated)</td>"
                        $html += "<td>$($rule.CreatedDate)</td>"
                        $html += "<td class='query-cell' title='$([System.Web.HttpUtility]::HtmlEncode($rule.Query))'>$([System.Web.HttpUtility]::HtmlEncode($rule.Query))</td></tr>`n"
                    }
                    $html += "</table>`n"
                }
            }
            else {
                $html += "<table><tr><th>Rule Name</th><th>Status</th><th>Severity</th><th>Creator</th><th>Alerts</th><th>Created</th><th>Account</th><th>Site</th></tr>`n"
                foreach ($rule in ($scopeGroup.Group | Sort-Object CreatedDate -Descending)) {
                    $statusClass = if ($rule.Status -eq "Enabled") { "status-enabled" } else { "status-disabled" }
                    $severityClass = "severity-" + $rule.Severity.ToLower()
                    $html += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($rule.RuleName))</td>"
                    $html += "<td class='$statusClass'>$($rule.Status)</td>"
                    $html += "<td class='$severityClass'>$($rule.Severity)</td>"
                    $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($rule.Creator))</td>"
                    $html += "<td>$($rule.AlertsGenerated)</td>"
                    $html += "<td>$($rule.CreatedDate)</td>"
                    $html += "<td>$($rule.AccountName)</td>"
                    $html += "<td>$($rule.SiteName)</td></tr>`n"
                }
                $html += "</table>`n"
            }
            
            $html += "</div>`n"
        }
        
        $html += "</body></html>"
        
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
    }
}

Write-Host "`nScript completed successfully." -ForegroundColor Green
