# Manage-MgUserAuthenticationMethods
A script to check and clear MFA methods in Azure AD using the Microsoft.Graph module.
The "Beta" script is using the Beta Microsoft Graph API. When the necessary functions are moved to GA, the script will be updated to avoid issues related to changes in the Beta api functions.
The script can also get recent MFA sign ins/failures for a user to assist troubleshooting.
This is essentially a fork of Manage-AzureADMFAMethods.

However, there is not feature parity between the two scripts due to a mismatch of features in MSOnline Powershell, AzureAD Powershell, and Microsoft Graph Powershell.
For example, if you need to know the default MFA method or view the full phone number without granting higher access than Authentication Administrator, the MS Graph script will not work for you.

## Usage
Install the Microsoft Graph module. We're cross platform now!
Download and run from a Powershell session (.\Manage-MgUserAuthenticationMethodsBeta.ps1)
You'll need to make sure you have Global Admin/Authentication Admin role in AAD.
The script uses modern authentication and is compatible with MFA.

Use the menu to navigate the script.

### Functions
0: Set User. A user must be set first to use the script's functions.
1. Get registered MFA Methods and Details for User
2. Clear MFA Registration for User
3. Get Detailed Sign In Log
4. Get MFA Summary
5. Get Sign In Summary
6. Revoke Refresh Tokens (Require re-authentication) 
