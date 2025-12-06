<#
.SYNOPSIS
    Generates a comprehensive report of all SentinelOne users and their scopes/roles.

.DESCRIPTION
    This script retrieves all users from SentinelOne (both regular users and service users)
    and creates a detailed report showing their assigned roles at different scope levels
    (Account, Site, Group). The report includes user details, scope assignments, role
    information, and access status.

.PARAMETER ManagementServer
    The SentinelOne management console URL (e.g., https://your-console.sentinelone.net)

.PARAMETER ApiToken
    API token for authentication. Must have permissions to view users and roles.

.PARAMETER IncludeServiceUsers
    Include service users (API accounts) in the report. Default is $true.

.PARAMETER OutputFormat
    Export format: Console, CSV, JSON, HTML, or All. Default is Console.

.PARAMETER OutputPath
    Directory path for exported files. Defaults to current directory.

.EXAMPLE
    .\Get-S1UserReport.ps1 -ManagementServer "https://your-console.sentinelone.net" -ApiToken "your-api-token"
    
    Displays user roles report in console.

.EXAMPLE
    .\Get-S1UserReport.ps1 -ManagementServer "https://your-console.sentinelone.net" -ApiToken "your-api-token" -OutputFormat All -OutputPath "C:\Reports"
    
    Exports report in all formats to specified directory.

.EXAMPLE
    .\Get-S1UserReport.ps1 -ManagementServer "https://your-console.sentinelone.net" -ApiToken "your-api-token" -IncludeServiceUsers $false -OutputFormat CSV
    
    Exports regular users only (excluding service users) to CSV.

.NOTES
    Author: Geoff Tankersley
    Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ManagementServer,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiToken,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeServiceUsers = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Console','CSV','JSON','HTML','All')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'Stop'

$headers = @{
    'Authorization' = "ApiToken $ApiToken"
    'Content-Type' = 'application/json'
}

$baseUrl = $ManagementServer.TrimEnd('/')

function Get-AllUsers {
    Write-Host "Retrieving regular users..." -ForegroundColor Cyan
    
    $allUsers = @()
    $cursor = $null
    $limit = 1000
    
    do {
        $queryParams = @{
            limit = $limit
        }
        
        if ($cursor) {
            $queryParams['cursor'] = $cursor
        }
        
        $queryString = ($queryParams.GetEnumerator() | ForEach-Object { 
            "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))" 
        }) -join '&'
        
        $uri = "$baseUrl/web/api/v2.1/users?$queryString"
        
        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            
            if ($response.data) {
                $allUsers += $response.data
                Write-Host "  Retrieved $($response.data.Count) users (Total: $($allUsers.Count))" -ForegroundColor Gray
            }
            
            $cursor = $response.pagination.nextCursor
            
        } catch {
            Write-Warning "Error retrieving users: $_"
            break
        }
        
    } while ($cursor)
    
    Write-Host "  Total regular users retrieved: $($allUsers.Count)" -ForegroundColor Green
    return $allUsers
}

function Get-AllServiceUsers {
    Write-Host "Retrieving service users..." -ForegroundColor Cyan
    
    $allServiceUsers = @()
    $cursor = $null
    $limit = 1000
    
    do {
        $queryParams = @{
            limit = $limit
        }
        
        if ($cursor) {
            $queryParams['cursor'] = $cursor
        }
        
        $queryString = ($queryParams.GetEnumerator() | ForEach-Object { 
            "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))" 
        }) -join '&'
        
        $uri = "$baseUrl/web/api/v2.1/service-users?$queryString"
        
        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            
            if ($response.data) {
                $allServiceUsers += $response.data
                Write-Host "  Retrieved $($response.data.Count) service users (Total: $($allServiceUsers.Count))" -ForegroundColor Gray
            }
            
            $cursor = $response.pagination.nextCursor
            
        } catch {
            Write-Warning "Error retrieving service users: $_"
            break
        }
        
    } while ($cursor)
    
    Write-Host "  Total service users retrieved: $($allServiceUsers.Count)" -ForegroundColor Green
    return $allServiceUsers
}

function Format-UserRoleData {
    param($users, [string]$userType)
    
    $formattedData = @()
    
    foreach ($user in $users) {
        $baseUserInfo = [PSCustomObject]@{
            UserType = $userType
            UserId = $user.id
            FullName = if ($userType -eq 'Regular') { $user.fullName } else { $user.name }
            Email = $user.email
            Description = $user.description
            Scope = $user.scope
            DateJoined = if ($userType -eq 'Regular') { $user.dateJoined } else { $user.createdAt }
            FirstLogin = $user.firstLogin
            LastLogin = $user.lastLogin
            TwoFactorEnabled = $user.twoFaEnabled
            EmailVerified = if ($userType -eq 'Regular') { $user.emailVerified } else { 'N/A' }
            ApiTokenExpiration = if ($user.apiToken) { $user.apiToken.expiresAt } else { 'None' }
        }
        
        if ($user.scopeRoles -and $user.scopeRoles.Count -gt 0) {
            foreach ($scopeRole in $user.scopeRoles) {
                $entry = $baseUserInfo.PSObject.Copy()
                $entry | Add-Member -NotePropertyName 'ScopeType' -NotePropertyValue 'Account/Group'
                $entry | Add-Member -NotePropertyName 'ScopeName' -NotePropertyValue $scopeRole.name
                $entry | Add-Member -NotePropertyName 'ScopeId' -NotePropertyValue $scopeRole.id
                $entry | Add-Member -NotePropertyName 'RoleId' -NotePropertyValue $scopeRole.roleId
                $entry | Add-Member -NotePropertyName 'RoleName' -NotePropertyValue $scopeRole.roleName
                
                $rolesString = if ($scopeRole.roles) { $scopeRole.roles -join ', ' } else { '' }
                $entry | Add-Member -NotePropertyName 'Roles' -NotePropertyValue $rolesString
                
                $formattedData += $entry
            }
        }
        
        if ($user.siteRoles -and $user.siteRoles.Count -gt 0) {
            foreach ($siteRole in $user.siteRoles) {
                $entry = $baseUserInfo.PSObject.Copy()
                $entry | Add-Member -NotePropertyName 'ScopeType' -NotePropertyValue 'Site'
                $entry | Add-Member -NotePropertyName 'ScopeName' -NotePropertyValue $siteRole.name
                $entry | Add-Member -NotePropertyName 'ScopeId' -NotePropertyValue $siteRole.id
                $entry | Add-Member -NotePropertyName 'RoleId' -NotePropertyValue $siteRole.roleId
                $entry | Add-Member -NotePropertyName 'RoleName' -NotePropertyValue $siteRole.roleName
                
                $rolesString = if ($siteRole.roles) { $siteRole.roles -join ', ' } else { '' }
                $entry | Add-Member -NotePropertyName 'Roles' -NotePropertyValue $rolesString
                
                $formattedData += $entry
            }
        }
        
        if ((-not $user.scopeRoles -or $user.scopeRoles.Count -eq 0) -and 
            (-not $user.siteRoles -or $user.siteRoles.Count -eq 0)) {
            $entry = $baseUserInfo.PSObject.Copy()
            $entry | Add-Member -NotePropertyName 'ScopeType' -NotePropertyValue 'No Roles Assigned'
            $entry | Add-Member -NotePropertyName 'ScopeName' -NotePropertyValue ''
            $entry | Add-Member -NotePropertyName 'ScopeId' -NotePropertyValue ''
            $entry | Add-Member -NotePropertyName 'RoleId' -NotePropertyValue ''
            $entry | Add-Member -NotePropertyName 'RoleName' -NotePropertyValue ''
            $entry | Add-Member -NotePropertyName 'Roles' -NotePropertyValue ''
            
            $formattedData += $entry
        }
    }
    
    return $formattedData
}

function Export-ToCSV {
    param($data, $filename)
    
    $csvPath = Join-Path $OutputPath $filename
    $data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV report exported to: $csvPath" -ForegroundColor Green
}

function Export-ToJSON {
    param($data, $filename)
    
    $jsonPath = Join-Path $OutputPath $filename
    $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "JSON report exported to: $jsonPath" -ForegroundColor Green
}

function Export-ToHTML {
    param($data, $filename)
    
    $htmlPath = Join-Path $OutputPath $filename
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>SentinelOne User Roles Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; border-bottom: 2px solid #5f249f; padding-bottom: 10px; }
        .summary { background-color: white; padding: 15px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-top: 20px; }
        th { background-color: #5f249f; color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        tr:nth-child(even) { background-color: #fafafa; }
        .user-type-regular { color: #0066cc; font-weight: bold; }
        .user-type-service { color: #cc6600; font-weight: bold; }
        .no-roles { color: #999; font-style: italic; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>SentinelOne User Roles Report</h1>
    <div class="summary">
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Total Users:</strong> $($data.Count) role assignments</p>
        <p><strong>Unique Users:</strong> $(($data | Select-Object -Unique UserId).Count)</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>User Type</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Scope Type</th>
                <th>Scope Name</th>
                <th>Role Name</th>
                <th>Date Joined</th>
                <th>2FA Enabled</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($item in $data) {
        $userTypeClass = if ($item.UserType -eq 'Regular') { 'user-type-regular' } else { 'user-type-service' }
        $roleClass = if ($item.ScopeType -eq 'No Roles Assigned') { 'no-roles' } else { '' }
        
        $html += @"
            <tr>
                <td class="$userTypeClass">$($item.UserType)</td>
                <td>$($item.FullName)</td>
                <td>$($item.Email)</td>
                <td class="$roleClass">$($item.ScopeType)</td>
                <td>$($item.ScopeName)</td>
                <td>$($item.RoleName)</td>
                <td>$($item.DateJoined)</td>
                <td>$($item.TwoFactorEnabled)</td>
            </tr>
"@
    }
    
    $html += @"
        </tbody>
    </table>
    <div class="timestamp">Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
}

function Display-ConsoleReport {
    param($data)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "SentinelOne User Roles Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Total Role Assignments: $($data.Count)" -ForegroundColor Gray
    Write-Host "Unique Users: $(($data | Select-Object -Unique UserId).Count)" -ForegroundColor Gray
    Write-Host ""
    
    $groupedByUser = $data | Group-Object -Property UserId
    
    foreach ($userGroup in $groupedByUser) {
        $firstEntry = $userGroup.Group[0]
        
        Write-Host "========================================" -ForegroundColor Yellow
        
        if ($firstEntry.UserType -eq 'Regular') {
            Write-Host "USER: $($firstEntry.FullName)" -ForegroundColor White
        } else {
            Write-Host "SERVICE USER: $($firstEntry.FullName)" -ForegroundColor Magenta
        }
        
        Write-Host "  Email: $($firstEntry.Email)" -ForegroundColor Gray
        Write-Host "  User ID: $($firstEntry.UserId)" -ForegroundColor Gray
        Write-Host "  User Scope: $($firstEntry.Scope)" -ForegroundColor Gray
        Write-Host "  Date Joined: $($firstEntry.DateJoined)" -ForegroundColor Gray
        
        if ($firstEntry.UserType -eq 'Regular') {
            Write-Host "  2FA Enabled: $($firstEntry.TwoFactorEnabled)" -ForegroundColor Gray
            Write-Host "  Email Verified: $($firstEntry.EmailVerified)" -ForegroundColor Gray
        }
        
        if ($firstEntry.ApiTokenExpiration -ne 'None') {
            Write-Host "  API Token Expiration: $($firstEntry.ApiTokenExpiration)" -ForegroundColor Gray
        }
        
        if ($firstEntry.Description) {
            Write-Host "  Description: $($firstEntry.Description)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "  Role Assignments:" -ForegroundColor Cyan
        
        foreach ($assignment in $userGroup.Group) {
            if ($assignment.ScopeType -eq 'No Roles Assigned') {
                Write-Host "    [!] No roles assigned" -ForegroundColor Red
            } else {
                Write-Host "    [$($assignment.ScopeType)] $($assignment.ScopeName)" -ForegroundColor White
                Write-Host "      Role: $($assignment.RoleName)" -ForegroundColor Green
                if ($assignment.RoleId) {
                    Write-Host "      Role ID: $($assignment.RoleId)" -ForegroundColor Gray
                }
                if ($assignment.Roles) {
                    Write-Host "      Legacy Roles: $($assignment.Roles)" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Summary by Role Assignment" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $roleStats = $data | Where-Object { $_.ScopeType -ne 'No Roles Assigned' } | 
                         Group-Object -Property RoleName | 
                         Sort-Object Count -Descending
    
    foreach ($role in $roleStats) {
        Write-Host "$($role.Name): $($role.Count) assignments" -ForegroundColor White
    }
    
    $noRolesCount = ($data | Where-Object { $_.ScopeType -eq 'No Roles Assigned' }).Count
    if ($noRolesCount -gt 0) {
        Write-Host "No Roles Assigned: $noRolesCount users" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "`nStarting SentinelOne User Roles Report..." -ForegroundColor Cyan
Write-Host "Management Server: $ManagementServer" -ForegroundColor Gray
Write-Host ""

$allData = @()

$regularUsers = Get-AllUsers
if ($regularUsers.Count -gt 0) {
    $formattedRegularUsers = Format-UserRoleData -users $regularUsers -userType 'Regular'
    $allData += $formattedRegularUsers
}

if ($IncludeServiceUsers) {
    $serviceUsers = Get-AllServiceUsers
    if ($serviceUsers.Count -gt 0) {
        $formattedServiceUsers = Format-UserRoleData -users $serviceUsers -userType 'Service'
        $allData += $formattedServiceUsers
    }
}

if ($allData.Count -eq 0) {
    Write-Warning "No users found."
    return
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

switch ($OutputFormat) {
    'Console' {
        Display-ConsoleReport -data $allData
    }
    'CSV' {
        Export-ToCSV -data $allData -filename "S1_UserRoles_$timestamp.csv"
    }
    'JSON' {
        Export-ToJSON -data $allData -filename "S1_UserRoles_$timestamp.json"
    }
    'HTML' {
        Export-ToHTML -data $allData -filename "S1_UserRoles_$timestamp.html"
    }
    'All' {
        Display-ConsoleReport -data $allData
        Export-ToCSV -data $allData -filename "S1_UserRoles_$timestamp.csv"
        Export-ToJSON -data $allData -filename "S1_UserRoles_$timestamp.json"
        Export-ToHTML -data $allData -filename "S1_UserRoles_$timestamp.html"
    }
}

Write-Host "`nReport generation complete!" -ForegroundColor Green
