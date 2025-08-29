# Microsoft Entra ID Application Credential Rotation PowerShell Script
This repository contains a powerful and flexible PowerShell script to automate the rotation of secrets and certificates for Microsoft Entra ID Applications at scale. It is designed to be run manually by an administrator for targeted operations or fully automated as part of your security and compliance workflow (e.g., in an Azure Automation Account).  

The script securely generates new credentials, stores them in Azure Key Vault for safe retrieval, and provides rich notification options to keep stakeholders informed.

## Key Features
- **Flexible Application Selection**: Identify applications for credential rotation based on:
  - **Expiration**: Target credentials expiring within a configurable number of days.
  - **Tagging**: Force an immediate rotation for any application with a specific tag.
- **Multiple Authentication Methods**: Run the script using various identities:
  - **Interactive**: For attended execution by a user or administrator with an interactive sign-in prompt.
  - **Service Principal**: For non-interactive, automated scenarios using a dedicated application identity.
  - **Managed Identity**: For secure, passwordless authentication from supported Azure resources like Azure Automation or Azure VMs.
- **Secure Credential Handling**: New secrets and certificates (with their private keys) are stored directly in **Azure Key Vault**, never exposed in logs or console output.
- **Customizable Certificate Generation**: Full control over self-signed certificate creation, including key algorithm, key length, and hash algorithm.
- **Robust Logging & Notifications**:
  - Detailed local log file for auditing every action.
  - Real-time notifications sent to **Microsoft Teams** or via **Email**.
- **Permission Verification**: Pre-flight check ensures the executing principal has the required Microsoft Graph API permissions before making any changes.

## Requirements
### 1. PowerShell Environment
- **PowerShell 7.2 or later** is recommended.
- Required PowerShell Modules:
  - **Microsoft.Graph**:
    ~~~powershell
    Install-Module Microsoft.Graph -Scope CurrentUser
    ~~~
  - **Az.KeyVault** (Part of the Az module framework):
    ~~~powershell
    Install-Module Az.KeyVault -Scope CurrentUser
    ~~~
### 2. Azure / Entra ID Permissions
The identity used to run the script (User, Service Principal, or Managed Identity) requires the following **Microsoft Graph API application permissions**:
- `Directory.Read.All`
- `Application.ReadWrite.All`
### 3. Azure Key Vault
- An existing Azure Key Vault is required.
- The identity running the script must have an access policy or RBAC role assigned that grants the following permissions:
  - **Secrets**: `Set`
  - **Certificates**: `Import`

## Installation and Setup
1. **Download the PowsherShell script file** or **Clone the Repository** (Optional)   
   ~~~
   git clone [https://github.com/pfguglielmi/Rotate-App-Credentials.git](https://github.com/pfguglielmi/Rotate-App-Credentials.git)`
   cd Rotate-App-Credentials
   ~~~
   

2. **Install PowerShell Modules**
   Open a PowerShell 7+ terminal and run:  
   \# Install the Microsoft Graph SDK
   ~~~powershell
   Install-Module Microsoft.Graph -Scope CurrentUser -Force
   ~~~

   \# Install the Azure Key Vault module
   ~~~powershell
   Install-Module Az.KeyVault -Scope CurrentUser -Force
   ~~~
   
4. **Configure Permissions for the Automation Principal**
   Choose one of the authentication methods and configure its permissions.
   - **For Managed Identity / Service Principal**:
     1. Navigate to your Managed Identity or App Registration in the Entra ID portal.
     2. Go to **API permissions**.
     3. Click **Add a permission**, select **Microsoft Graph**, then **Application permissions**.
     4. Search for and add `Directory.Read.All` and `Application.ReadWrite.All`.
     5. Click **Grant admin consent for [Your Tenant]**.
   - **For Azure Key Vault**:
     1. Navigate to your Key Vault in the Azure portal.
     2. Go to **Access control (IAM)**.
     3. Click **Add role assignment**.
     4. Assign a role like **Key Vault Secrets Officer** and **Key Vault Certificate Officer** to the principal that will run the script.
   - **(Optional) Configure Notifications**
     - **For Teams**: Create an [Incoming Webhook](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) for your desired channel and copy the URL.
     - **For Email**: Ensure you have access to an SMTP server that the script can use to send emails.

## Usage
The script is run from the command line with parameters to control its behavior.

### Example 1: Interactive Run for Expiring Secrets
An administrator can run this command to manually rotate secrets expiring in the next 30 days. The script will prompt for an interactive login.  
~~~powershell
.\Rotate-App-Credentials.ps1 -SelectionMethod Expiration `
    -AuthMethod Interactive `
    -TenantId "your-tenant-id.onmicrosoft.com" `
    -CredentialType Secret `
    -KeyVaultName "your-key-vault-name" `
    -NotificationType Teams `
    -TeamsWebhookUrl "https://your-webhook-url"
~~~

### Example 2: Fully Automated Run with Managed Identity
This example is ideal for an Azure Automation runbook. It rotates both secrets and certificates, and safely removes the old credentials after a successful rotation.
~~~powershell
.\Rotate-App-Credentials.ps1 -SelectionMethod Expiration `
    -AuthMethod ManagedIdentity `
    -CredentialType Both `
    -KeyVaultName "prod-credential-vault" `
    -RemoveOldCredential $true `
    -NotificationType Email `
    -EmailTo "security-admins@yourcompany.com" `
    -EmailFrom "automation@yourcompany.com" `
    -SmtpServer "smtp.yourcompany.com"
~~~

### Example 3: Forced Rotation for Tagged Applications
This command forces an immediate rotation of certificates for all applications that have been tagged with CriticalApp-RotateNow. It uses a Service Principal for authentication.
~~~powershell
.\Rotate-App-Credentials.ps1 -SelectionMethod Tag `
    -TagName "CriticalApp-RotateNow" `
    -AuthMethod ServicePrincipal `
    -TenantId "your-tenant-id.onmicrosoft.com" `
    -ClientId "spn-client-id" `
    -CertificateThumbprint "spn-cert-thumbprint" `
    -CredentialType Certificate `
    -KeyVaultName "your-key-vault-name"
~~~

### Example 4: Custom Certificate GenerationThis example demonstrates how to generate a new certificate with a stronger RSA key and SHA512 hashing algorithm.
~~~powershell
.\Rotate-App-Credentials.ps1 -SelectionMethod Expiration `
    -AuthMethod Interactive `
    -CredentialType Certificate `
    -KeyVaultName "your-key-vault-name" `
    -CertKeyLength 4096 `
    -CertHashAlgorithm SHA512
~~~

## Parameter Reference
The following table details all available parameters for the script.
| Parameter             | Type    | Description                                                                 | Required? | Default Value        |
|-----------------------|---------|-----------------------------------------------------------------------------|-----------|----------------------|
| SelectionMethod       | String  | How to identify apps. Expiration or Tag.                                    | Yes       |                      |
| TagName               | String  | The tag to search for if SelectionMethod is Tag.                            | No        |                      |
| KeyVaultName          | String  | The name of the Azure Key Vault to store                                    | Yes       |                      |
| CredentialType        | String  | Type of credential to rotate. Secret, Certificate, or Both.                 | No        | Secret               |
| ExpirationDays        | Int     | The number of days to look ahead for expiring credentials.                  | No        | 30                   |
| RemoveOldCredential   | Boolean | If $true, the old credential will be deleted after rotation.                | No        | $false               |
| AuthMethod            | String  | Authentication method. ManagedIdentity, ServicePrincipal, or Interactive.   | Yes       |                      |
| TenantId              | String  | Tenant ID, required for ServicePrincipal and Interactive auth.              | No        |                      |
| ClientId              | String  | Client ID, required for ServicePrincipal auth.                              | No        |                      |
| CertificateThumbprint | String  | Cert thumbprint, required for ServicePrincipal auth.                        | No        |                      |
| CertKeyAlgorithm      | String  | Key algorithm for new certs. RSA or ECDSA.                                  | No        | RSA                  |
| CertKeyLength         | Int     | Key length for new RSA certs. 2048, 3072, or 4096.                          | No        | 2048                 |
| CertHashAlgorithm     | String  | Hash algorithm for new certificates. SHA256, SHA384, SHA512.                | No        | SHA256               |
| CertStoreLocation     | String  | Local path for temporary cert creation.                                     | No        | Cert:\CurrentUser\My |
| NotificationType      | String  | Notification channel. Teams, Email, or None.                                | No        |                      |
| TeamsWebhookUrl       | String  | Webhook URL for Teams notifications.                                        | No        |                      |
| EmailTo               | String  | Recipient email address.                                                    | No        |                      |
| EmailFrom             | String  | Sender email address.                                                       | No        |                      |
| SmtpServer            | String  | SMTP server for email.                                                      | No        |                      |

## Contributing
Contributions are welcome! Please feel free to open an issue or submit a pull request.
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## License 
This project is licensed under the [MIT License](https://github.com/pfguglielmi/Rotate-App-Credentials/tree/main?tab=MIT-1-ov-file). See the LICENSE file for details.
