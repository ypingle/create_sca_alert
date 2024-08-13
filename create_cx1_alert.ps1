# Function to parse a simple YAML file manually
function Parse-Yaml {
    param (
        [string]$YamlFile
    )

    $YamlContent = Get-Content $YamlFile
    $Config = @{}

    foreach ($line in $YamlContent) {
        if ($line -match "^\s*#") { continue }  # Skip comments
        if ($line -match "^\s*$") { continue }  # Skip empty lines

        $key, $value = $line -split ":", 2
        $Config[$key.Trim()] = $value.Trim()
    }

    return $Config
}

# Load the YAML file using the custom parser
$Config = Parse-Yaml 'config_cx1.yaml'

$CX1_tenant = $Config['CX1_tenant']
$CX1_clientid = $Config['CX1_clientid']
$CX1_secret = $Config['CX1_secret']
$CX1_api_url = $Config['CX1_api_url']
$SMTP_server = $Config['SMTP_server']
$SMTP_port = $Config['SMTP_port']
$SMTP_tls = $Config['SMTP_tls']
$SMTP_user = $Config['SMTP_user']
$SMTP_password = $Config['SMTP_password']
$Email_from = $Config['Email_from']
$Email_subject = $Config['Email_subject']

# Function to send email
function Send-Email {
    param (
        [string]$MySender,
        [string]$EmailRecipients,
        [string]$Subject,
        [string]$Body
    )
    
    $RecipientsList = $EmailRecipients -split ',' | ForEach-Object { $_.Trim() }
    $message = New-Object Net.Mail.MailMessage
    $message.From = $MySender
    $message.Subject = $Subject
    $message.Body = $Body
    $RecipientsList | ForEach-Object { $message.To.Add($_) }

    try {
        $smtp = New-Object Net.Mail.SmtpClient($SMTP_server, $SMTP_port)
        if ($SMTP_tls) {
            $smtp.EnableSsl = $true
        }
        if ($SMTP_user -and $SMTP_password) {
            $smtp.Credentials = New-Object Net.NetworkCredential($SMTP_user, $SMTP_password)
        }
        $smtp.Send($message)
    } catch {
        Write-Host "Exception: Failed to send email: $_"
    }
}

# Function to get access token
function Get-AccessToken {
    try {
        $url = "https://eu.iam.checkmarx.net/auth/realms/$CX1_tenant/protocol/openid-connect/token"
        $payload = @{
            'client_id' = $CX1_clientid
            'grant_type' = 'client_credentials'
            'client_secret' = $CX1_secret
        }
        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
            'Accept' = 'application/json'
        }
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $payload  
        return $response.access_token
    } catch {
        Write-Host "Exception: Failed to get access token: $_"
        return ""
    }
}

# Function to get project latest scan ID
function Get-ProjectLatestScanId {
    param (
        [string]$AccessToken,
        [string]$ProjectName,
        [string]$ProjectId
    )

    if (-not $ProjectId) {
        $ProjectId = Get-ProjectId -AccessToken $AccessToken -ProjectName $ProjectName
    }

    if ($ProjectId) {
        $url = "$CX1_api_url/projects/last-scan?project-ids=$ProjectId"
        try {
            $headers = @{
                'Authorization' = "Bearer $AccessToken"
            }
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers  
            $created_at_str = $response.$ProjectId.createdAt
            $created_at_str = $created_at_str -replace "\.\d+Z", "Z"

            # Parse the datetime string
            $created_at = [datetime]::ParseExact($created_at_str, "yyyy-MM-ddTHH:mm:ssZ", $null)  
            return $response.$ProjectId.id, $created_at
        } catch {
            Write-Host "Exception: Get-ProjectLatestScanId: $_"
            return ""
        }
    } else {
        return ""
    }
}

# Function to get projects
function Get-Projects {
    param (
        [string]$AccessToken
    )

    if (-not $AccessToken) {
        $AccessToken = Get-AccessToken
    }

    try {
        $url = "$CX1_api_url/projects"
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
        }
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers  
        return $response.projects
    } catch {
        Write-Host "Exception: Failed to get projects: $_"
        return ""
    }
}

# Function to get project ID by name
function Get-ProjectId {
    param (
        [string]$AccessToken,
        [string]$ProjectName
    )

    try {
        $url = "$CX1_api_url/projects"
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
        }
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers  
        $project_id = $null

        foreach ($project in $response.projects) {
            if ($project.name -eq $ProjectName) {
                $project_id = $project.id
                break
            }
        }
        Write-Host "Get-ProjectId id: $project_id"
        return $project_id
    } catch {
        Write-Host "Exception: Failed to get project ID: $_"
        return ""
    }
}

# Function to get SCA results
function Get-ScaResults {
    param (
        [string]$ProjectName,
        [string]$ProjectId,
        [string]$IntervalMinutes
    )

    $AccessToken = Get-AccessToken
    if ($AccessToken) {
        $scan_id, $created_at = Get-ProjectLatestScanId -AccessToken $AccessToken -ProjectName $ProjectName -ProjectId $ProjectId

        if ($scan_id) {
            if ($IntervalMinutes) {
                $current_time = (Get-Date).ToUniversalTime()
                $interval = New-TimeSpan -Minutes $IntervalMinutes
                $start_time = $current_time - $interval
                $end_time = $current_time

                if ($start_time -lt $created_at -and $created_at -lt $end_time) {
                    $url = "$CX1_api_url/scan-summary?scan-ids=$scan_id"
                    try {
                        $headers = @{
                            'Authorization' = "Bearer $AccessToken"
                        }
                        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers  
                        $counters = $response.scansSummaries[0].scaCounters
                        $high_counter = $counters.severityCounters[1].counter
                        $medium_counter = $counters.severityCounters[0].counter
                        return $high_counter, $medium_counter
                    } catch {
                        Write-Host "Exception: Get-ScaResults: $_"
                        return ""
                    }
                } else {
                    return 0, 0
                }
            }
        }
    }
}

# Main function to execute the script
function Main {
    param (
        [string]$EmailRecipients,
        [string]$Interval
    )

    if (-not $EmailRecipients -or -not $Interval) {
        Write-Host 'Usage: .\Create_cx1_alert.ps1 -EmailRecipients <notification email> -Interval <interval>'
        exit
    }

    Write-Host "Email recipients: $EmailRecipients"
    Write-Host "Interval: $Interval"

    $ProjectList = Get-Projects

    foreach ($Project in $ProjectList) {
        $ProjectName = $Project.name
        $ProjectId = $Project.id

        $HighCount, $MediumCount = Get-ScaResults -ProjectName $ProjectName -ProjectId $ProjectId -IntervalMinutes $Interval

        Write-Host "Project: $ProjectName`n$HighCount high vulnerabilities`n$MediumCount medium vulnerabilities"

        if ($HighCount -gt 0 -or $MediumCount -gt 0) {
            $EmailBody = "Project: $ProjectName`n$HighCount high vulnerabilities`n$MediumCount medium vulnerabilities"
            Send-Email -MySender $Email_from -EmailRecipients $EmailRecipients -Subject $Email_subject -Body $EmailBody
        }
    }
}

# Run the main function
Main -EmailRecipients $args[0] -Interval $args[1]
