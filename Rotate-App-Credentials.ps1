<#
.SYNOPSIS
    Automates the rotation of Microsoft Entra ID Application secrets and/or certificates.
.DESCRIPTION
    This script identifies application credentials for rotation based on expiration or tags. It first verifies that
    the executing principal has the required MS Graph API permissions.

    It supports multiple authentication methods, including interactive user login. For each identified credential, 
    it generates a new one, securely stores it in Azure Key Vault, and (optionally) removes the old one.
.PARAMETER SelectionMethod
    Specifies how to identify applications for credential rotation.
    - 'Expiration': Identifies applications with credentials expiring soon.
    - 'Tag': Identifies applications by a specific tag. All credentials on tagged apps will be targeted for rotation.
.PARAMETER TagName
    The tag to search for when using the 'Tag' selection method (e.g., 'Recovered' or 'Restored').
.PARAMETER AuthMethod
    Specifies the authentication method ('ManagedIdentity', 'ServicePrincipal', or 'Interactive').
.PARAMETER CredentialType
    Specifies the type of credential to rotate ('Secrets', 'Certificates', or 'Both').
.PARAMETER NotificationType
    Specifies the notification method ('Teams', 'Email', or 'None').
.EXAMPLE
    # Rotate expiring secrets for all apps using interactive user login and notify Teams
    .\Rotate-App-Credentials.ps1 -SelectionMethod Expiration -AuthMethod Interactive -CredentialType Secrets -NotificationType Teams -KeyVaultName 'my-prod-kv' -TeamsWebhookUrl 'https://...'

.EXAMPLE
    # Force-rotate all certificates on applications tagged with 'CriticalApp' using a Service Principal
    .\Rotate-App-Credentials.ps1 -SelectionMethod Tag -TagName 'CriticalApp' -AuthMethod ServicePrincipal -TenantId '...' -ClientId '...' -CertificateThumbprint '...' -CredentialType Certificates -NotificationType Email -EmailTo 'admin@contoso.com' -EmailFrom 'noreply@contoso.com' -SmtpServer 'smtp.contoso.com'

.NOTES
    Author: Pierre-François Guglielmi / Rubrik Speciality Engineering Team
    Version: 2.4
    Created: 2025-08-27
    Prerequisites: Microsoft.Graph and Az.KeyVault modules.
#>
[CmdletBinding()]
param(
    # --- Core Logic Parameters ---
    [Parameter(Mandatory=$true, HelpMessage="Method to identify applications for rotation. Options are Expiration or Tag")]
    [ValidateSet('Expiration', 'Tag')]
    [string]$SelectionMethod,

    [Parameter(Mandatory=$false, HelpMessage="The tag to identify applications when SelectionMethod is 'Tag'.")]
    [string]$TagName,

    [Parameter(Mandatory=$true, HelpMessage="The name of the Azure Key Vault for storing new credentials.")]
    [string]$KeyVaultName,

    # Suppressing false positive from PSScriptAnalyzer: This parameter defines a credential TYPE, not a credential itself.
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPasswords", "CredentialType")]
    [Parameter(Mandatory=$false, HelpMessage="Type of credential to rotate. Options are Secrets, Certificates or Both")]
    [ValidateSet('Secrets', 'Certificates', 'Both')]
    [string]$CredentialType = 'Secrets',

    [Parameter(Mandatory=$false, HelpMessage="Find credentials expiring in the next N days (used with 'Expiration' method).")]
    [int]$ExpirationDays = 30,

    [Parameter(Mandatory=$false, HelpMessage="If $true, the script will delete the old credential.")]
    [bool]$RemoveOldCredential = $false,

    # --- Authentication Parameters ---
    [Parameter(Mandatory=$true, HelpMessage="Authentication method. Options are ManagedIdentity, ServicePrincipal, or Interactive")]
    [ValidateSet('ManagedIdentity', 'ServicePrincipal', 'Interactive')]
    [string]$AuthMethod,

    [Parameter(Mandatory=$false, HelpMessage="Tenant ID for Service Principal or Interactive authentication.")]
    [string]$TenantId,

    [Parameter(Mandatory=$false, HelpMessage="Client ID for Service Principal authentication.")]
    [string]$ClientId,

    [Parameter(Mandatory=$false, HelpMessage="Certificate Thumbprint for Service Principal authentication.")]
    [string]$CertificateThumbprint,

    # --- Certificate Generation Parameters ---
    [Parameter(Mandatory=$false, HelpMessage="Key algorithm for new certificates. Options are RSA or ECDSA. Default is RSA")]
    [ValidateSet('RSA', 'ECDSA')]
    [string]$CertKeyAlgorithm = 'RSA',

    [Parameter(Mandatory=$false, HelpMessage="Key length for new RSA certificates. Options are 2048, 3072 or 4096. Default is 2048")]
    [ValidateSet(2048, 3072, 4096)]
    [int]$CertKeyLength = 2048,

    [Parameter(Mandatory=$false, HelpMessage="Hash algorithm for new certificates. Options are SHA256, SHA384 or SHA512. Defaut is SHA256")]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$CertHashAlgorithm = 'SHA256',

    [Parameter(Mandatory=$false, HelpMessage="Local store location for temporary certificate creation. Default location is Cert:\CurrentUser\My")]
    [string]$CertStoreLocation = 'Cert:\CurrentUser\My',

    # --- Notification Parameters ---
    [Parameter(Mandatory=$false, HelpMessage="Notification channel. Options are Teams, Email or Both. Default is None")]
    [ValidateSet('Teams', 'Email', 'None')]
    [string]$NotificationType = 'None',

    [Parameter(Mandatory=$false, HelpMessage="The incoming webhook URL for your Teams channel.")]
    [string]$TeamsWebhookUrl,

    [Parameter(Mandatory=$false, HelpMessage="Recipient email address.")]
    [string]$EmailTo,

    [Parameter(Mandatory=$false, HelpMessage="Sender email address.")]
    [string]$EmailFrom,

    [Parameter(Mandatory=$false, HelpMessage="SMTP server for email notifications.")]
    [string]$SmtpServer
)

#================================================================================
# SECTION 1: CONFIGURATION & VALIDATION
#================================================================================
# Validate parameter combinations
if ($SelectionMethod -eq 'Tag' -and -not $TagName) {
    throw "For 'Tag' selection method, you must provide a -TagName."
}
if ($AuthMethod -eq 'ServicePrincipal' -and (-not $TenantId -or -not $ClientId -or -not $CertificateThumbprint)) {
    throw "For 'ServicePrincipal' authentication, you must provide -TenantId, -ClientId, and -CertificateThumbprint."
}
if ($NotificationType -eq 'Teams' -and -not $TeamsWebhookUrl) {
    throw "For 'Teams' notifications, you must provide -TeamsWebhookUrl."
}
if ($NotificationType -eq 'Email' -and (-not $EmailTo -or -not $EmailFrom -or -not $SmtpServer)) {
    throw "For 'Email' notifications, you must provide -EmailTo, -EmailFrom, and -SmtpServer."
}

# --- Static Configuration ---
$logDirectory = "C:\temp\logs" # Local path to store log files.
$logFile = Join-Path $logDirectory "EntraAppCredentialRotation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$secretDisplayName = "AutoRotated-Secret-$(Get-Date -Format 'yyyy-MM-dd')"

#================================================================================
# SECTION 2: HELPER FUNCTIONS
#================================================================================

function Write-Log {
    param([string]$Message, [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $color = @{"INFO"="Green"; "WARN"="Yellow"; "ERROR"="Red"}[$Level]
    Write-Host $logEntry -ForegroundColor $color
    $logEntry | Out-File -FilePath $logFile -Append
}

function Send-Notification {
    param([string]$Title, [string]$Message, [string]$Status)
    
    if ($NotificationType -eq 'None') {
        Write-Log -Message "Notifications are disabled." -Level "WARN"
        return
    }

    Write-Log -Message "Sending notification via $NotificationType..."
    switch ($NotificationType) {
        'Teams' {
            $color = @{"good"="00FF00"; "warning"="FFFF00"; "danger"="FF0000"}[$Status]
            $payload = @{
                "@type" = "MessageCard"; themeColor = $color; summary = $Title
                sections = @(@{ activityTitle = $Title; text = $Message -replace '\n', '<br>'; markdown = $true })
            } | ConvertTo-Json
            try { Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post -Body $payload -ContentType 'application/json' }
            catch { Write-Log -Message "Failed to send Teams notification: $($_.Exception.Message)" -Level "ERROR" }
        }
        'Email' {
            $body = $Message -replace '\n', '<br>'
            try { Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $Title -Body $body -SmtpServer $SmtpServer -BodyAsHtml }
            catch { Write-Log -Message "Failed to send email notification: $($_.Exception.Message)" -Level "ERROR" }
        }
    }
}

function Test-MgGraphPermissions {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$RequiredPermissions
    )

    Write-Log -Message "Verifying required API permissions..."
    $context = Get-MgContext
    $grantedScopes = $context.Scopes

    $missingPermissions = @()
    foreach ($permission in $RequiredPermissions) {
        if ($grantedScopes -notcontains $permission) {
            $missingPermissions += $permission
        }
    }

    if ($missingPermissions.Count -gt 0) {
        $errorMessage = "The authenticated principal is missing the following required Microsoft Graph permissions: $($missingPermissions -join ', '). Please grant these permissions and try again."
        # This will be caught by the main try/catch block
        throw $errorMessage
    }

    Write-Log -Message "All required API permissions are present."
}


#================================================================================
# SECTION 3: SCRIPT EXECUTION
#================================================================================

# --- Initialize ---
if (-not (Test-Path $logDirectory)) { New-Item -Path $logDirectory -ItemType Directory | Out-Null }
$successes = [System.Collections.ArrayList]@()
$failures = [System.Collections.ArrayList]@()

Write-Log -Message "Starting Entra ID Application Credential Rotation Script."
Write-Log -Message "Selection Method: $SelectionMethod"
Write-Log -Message "Authentication Method: $AuthMethod"
Write-Log -Message "Credential Type: $CredentialType"

# --- Connect to Microsoft Graph and Verify Permissions ---
try {
    Write-Log -Message "Connecting to Microsoft Graph..."
    $requiredPermissions = @('Directory.Read.All', 'Application.ReadWrite.All')
    
    switch ($AuthMethod) {
        'ManagedIdentity' { Connect-MgGraph -Identity }
        'ServicePrincipal' { Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint }
        'Interactive' { Connect-MgGraph -TenantId $TenantId -Scopes $requiredPermissions }
    }
    Write-Log -Message "Connection successful."

    # --- Verify Permissions ---
    Test-MgGraphPermissions -RequiredPermissions $requiredPermissions
}
catch {
    $errorMessage = "Failed during connection or permission check. Error: $($_.Exception.Message)"
    Write-Log -Message $errorMessage -Level "ERROR"; Send-Notification -Title "SCRIPT FAILED" -Message $errorMessage -Status "danger"; exit 1
}

# --- Identify Target Applications ---
try {
    $properties = @('id', 'displayName', 'passwordCredentials', 'keyCredentials', 'tags')
    $applicationsToScan = @()

    if ($SelectionMethod -eq 'Tag') {
        Write-Log -Message "Identifying applications with tag: '$TagName'"
        $filter = "tags/any(t: t eq '$TagName')"
        $applicationsToScan = Get-MgApplication -Filter $filter -All -Property $properties
    } else { # Expiration
        Write-Log -Message "Identifying applications with credentials expiring in $ExpirationDays days."
        $applicationsToScan = Get-MgApplication -All -Property $properties
    }

    $appsToProcess = @()
    $expirationThreshold = (Get-Date).ToUniversalTime().AddDays($ExpirationDays)

    foreach ($app in $applicationsToScan) {
        $secretsToRotate = @()
        $certsToRotate = @()

        if ($CredentialType -in 'Secrets', 'Both') {
            $secretsToRotate = if ($SelectionMethod -eq 'Tag') {
                $app.PasswordCredentials
            } else {
                $app.PasswordCredentials | Where-Object { $_.EndDateTime -lt $expirationThreshold -and $_.EndDateTime -gt (Get-Date).ToUniversalTime() }
            }
        }
        if ($CredentialType -in 'Certificates', 'Both') {
            $certsToRotate = if ($SelectionMethod -eq 'Tag') {
                $app.KeyCredentials
            } else {
                $app.KeyCredentials | Where-Object { $_.EndDateTime -lt $expirationThreshold -and $_.EndDateTime -gt (Get-Date).ToUniversalTime() }
            }
        }
        
        if ($secretsToRotate.Count -gt 0 -or $certsToRotate.Count -gt 0) {
            Write-Log -Message "Found credentials to rotate for '$($app.DisplayName)'" -Level "WARN"
            $appsToProcess += [PSCustomObject]@{
                Id = $app.Id; DisplayName = $app.DisplayName
                SecretsToRotate = $secretsToRotate; CertsToRotate = $certsToRotate
            }
        }
    }
}
catch {
    $errorMessage = "Failed to query applications from Entra ID. Error: $($_.Exception.Message)"
    Write-Log -Message $errorMessage -Level "ERROR"; Send-Notification -Title "SCRIPT FAILED" -Message $errorMessage -Status "danger"; exit 1
}

if ($appsToProcess.Count -eq 0) {
    $summaryMessage = "No application credentials found matching the specified criteria."
    Write-Log -Message $summaryMessage; Send-Notification -Title "Credential Rotation: Summary" -Message $summaryMessage -Status "good"; exit 0
}

Write-Log -Message "Found $($appsToProcess.Count) applications with credentials to process."

# --- Main Processing Loop ---
foreach ($app in $appsToProcess) {
    Write-Log -Message "Processing application: '$($app.DisplayName)' (App ID: $($app.Id))"
    
    # --- Rotate Secrets ---
    if ($app.SecretsToRotate.Count -gt 0) {
        Write-Log -Message "  -> Rotating client secrets..."
        try {
            # Add a new secret first to ensure zero downtime
            $newSecret = Add-MgApplicationPassword -ApplicationId $app.Id -DisplayName $secretDisplayName
            if (!$newSecret.SecretText) { throw "Generated secret was empty." }
            
            $secretName = "$($app.DisplayName -replace '[^a-zA-Z0-9-]', '-')-secret"
            Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -SecretValue (ConvertTo-SecureString $newSecret.SecretText -AsPlainText -Force)
            Write-Log -Message "  -> New secret stored in Key Vault as '$secretName'."

            # Then remove the old credentials if enabled
            if ($RemoveOldCredential) {
                $app.SecretsToRotate | ForEach-Object {
                    Write-Log -Message "  -> Removing old secret (Key ID: $($_.KeyId))" -Level "WARN"
                    Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $_.KeyId
                }
            }
            [void]$successes.Add("Rotated Secret for $($app.DisplayName)")
        } catch {
            $errorMessage = "Failed to rotate secret for '$($app.DisplayName)'. Error: $($_.Exception.Message)"
            Write-Log -Message $errorMessage -Level "ERROR"; [void]$failures.Add($errorMessage)
        }
    }

    # --- Rotate Certificates ---
    if ($app.CertsToRotate.Count -gt 0) {
        Write-Log -Message "  -> Rotating certificates..."
        try {
            # Generate and add a new certificate using specified parameters
            $certParams = @{
                Subject = "CN=$($app.DisplayName)"
                CertStoreLocation = $CertStoreLocation
                KeyExportPolicy = 'Exportable'
                KeySpec = 'Signature'
                KeyAlgorithm = $CertKeyAlgorithm
                KeyLength = $CertKeyLength
                HashAlgorithm = $CertHashAlgorithm
            }
            $cert = New-SelfSignedCertificate @certParams
            
            $keyCredential = @{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData }
            Add-MgApplicationKey -ApplicationId $app.Id -KeyCredential $keyCredential -Proof "nonce"
            Write-Log -Message "  -> New certificate added to Entra application."

            # Store the certificate with its private key in Key Vault
            $certName = "$($app.DisplayName -replace '[^a-zA-Z0-9-]', '-')-cert"
            $kvCert = Import-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $certName -FilePath $cert.PSPath
            Write-Log -Message "  -> New certificate with private key stored in Key Vault as '$($kvCert.Name)'."
            Remove-Item -Path $cert.PSPath # Clean up local cert store

            # Then remove the old credentials if enabled
            if ($RemoveOldCredential) {
                $app.CertsToRotate | ForEach-Object {
                    Write-Log -Message "  -> Removing old certificate (Key ID: $($_.KeyId))" -Level "WARN"
                    Remove-MgApplicationKey -ApplicationId $app.Id -KeyId $_.KeyId
                }
            }
            [void]$successes.Add("Rotated Certificate for $($app.DisplayName)")
        } catch {
            $errorMessage = "Failed to rotate certificate for '$($app.DisplayName)'. Error: $($_.Exception.Message)"
            Write-Log -Message $errorMessage -Level "ERROR"; [void]$failures.Add($errorMessage)
        }
    }
}

# --- Final Summary and Notification ---
Write-Log -Message "Script finished processing."
$summaryTitle = "Entra ID Credential Rotation: Summary"
$summaryMessage = "Processed $($appsToProcess.Count) applications.`n`n"
$summaryStatus = "good"

if ($successes.Count -gt 0) {
    $summaryMessage += "**✅ Successes ($($successes.Count)):**`n - $($successes -join "`n - ")"
}
if ($failures.Count -gt 0) {
    $summaryStatus = "danger"
    $summaryMessage += "`n`n**❌ Failures ($($failures.Count)):**`n - $($failures -join "`n - ")"
}

Write-Log -Message $summaryMessage
Send-Notification -Title $summaryTitle -Message $summaryMessage -Status $summaryStatus

Write-Log -Message "Script execution complete."
