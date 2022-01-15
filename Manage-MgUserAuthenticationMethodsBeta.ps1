<#
.DESCRIPTION
    Manage-MgUserAuthenticationMethods allows Azure AD administrators to delete a user's
    enrolled MFA methods and view information regarding recent sign in attempts. 

.DEPENDENCIES
    You must be a global administrator or authentication administrator to use these roles.
    You need the Microsoft.Graph powershell module installed (cross platform)
    NOTE: Authentication Administrator role alone can only view masked phone numbers

.NOTES
    Version       : 3.0.1 - Manage-AzureADMFAMethods Fork - MSGraph Upgrade
    Author        : Blake Bourgeois
    Creation Date : 8/17/2019
    Last Edited   : 01/15/2022

#>

# Variable used to stay in the program or exit
$EnterScript = 0

# Function checks for connection to Azure, and initates one if necessary
function Check-MgGraphStatus{

            write-host "   Connecting to Microsoft Graph... You may be prompted to complete sign on in your browser." -ForegroundColor Yellow
            write-host ""
            # These scopes are needed for managing authentication methods and viewing logs
            # Any additional scopes required should be included here or invoked at time of call
            # unlike the old authentication method, this is painless if you have an existing session
            # we should always invoke it to ensure there are not unexpected profile or scopes attached to the session
            # when these graph endpoints are moved to GA the script should stop using the beta profile
            Select-MgProfile -Name "beta"
            Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","UserAuthenticationMethod.ReadWrite.All","AuditLog.Read.All","Directory.Read.All"
        
}

function Get-MgMFAMethods($upn){
    # This function pulls all the user info and displays it
    # TODO: if it becomes possible to determine the user's default MFA method, highlight it
    #   This is not available as of today (jan 2022)
    $enrollments = ""
    $enrollments = get-MgUserAuthenticationMethod -UserID $upn

    # the user's password method is expected to be available as an authentication method
    # truly passwordless orgs would need to change this logic
    if($enrollments.length -gt 1){
        #initialize all the variables to prevent orphaned entries skewing results
        $mobilenumber = ""
        $alternatephone = ""
        $officephone = ""
        $msAuthApps = @()
        $SoftwareOathApps = @()
        $fidoKeys = @()    
        $msPasswordless = ""    
        foreach($enrollment in $enrollments){

            # mobile, alt, and office phones have static IDs
            if($enrollment.ID -eq "3179e48a-750b-4051-897c-87b9720928f7"){
                $mobilenumber = ($enrollment.AdditionalProperties).phoneNumber
            }
            if($enrollment.ID -eq "b6332ec1-7057-4abe-9331-3d72feddfe41"){
                $alternatephone = ($enrollment.AdditionalProperties).phoneNumber
            }
            if($enrollment.ID -eq "e37fc753-ff3b-4958-9484-eaa9425c82bc"){
                $officephone = ($enrollment.AdditionalProperties).phoneNumber
            }
            if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"){
                $appDisplayName = ""
                $appDeviceTag = ""
                $appDisplayName = ($enrollment.AdditionalProperties).displayName
                $appDeviceTag = ($enrollment.AdditionalProperties).deviceTag
                # it is possible that users have multiple MS Authenticator enrollments
                $msAuthApps = $msAuthApps + "Microsoft Authenticator: $appDisplayName ($appDeviceTag)"
            }
            if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.softwareOathAuthenticationMethod"){
                $totpID = ""
                $totpID = $enrollment.ID
                $SoftwareOathApps = $SoftwareOathApps + "Software Code Generator (ID: $totpID)"
            }
            if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod"){
                $appDisplayName = ""
                $createdDateTime = ""
                $appDisplayName = ($enrollment.AdditionalProperties).displayName
                $createdDateTime = ($enrollment.AdditionalProperties).createdDateTime
                $createdDateTime = get-date $createdDateTime
                $createdDateTime = $createdDateTime.ToLocalTime()
                # users can only have a single passwordless enrollment for MS Auth so it does not require the same logic as above
                $msPasswordless = "Microsoft Authenticator: $appDisplayName (configured $createdDateTime)"

            }
            if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.fido2AuthenticationMethod"){
                $fidoDisplay = ""
                $createdDateTime = ""
                $model = ""
                $fidoDisplay = ($enrollment.AdditionalProperties).displayName
                $createdDateTime = ($enrollment.AdditionalProperties).createdDateTime
                $createdDateTime = get-date $createdDateTime
                $createdDateTime = $createdDateTime.ToLocalTime()
                $model = ($enrollment.AdditionalProperties).model
                $fidoKeys = $fidoKeys + "FIDO2: $model key $fidoDisplay (configured $createdDateTime)"
            }
        }

        # the user must have a mobile number enrolled to have an alternate or office available
        # if mobile number isn't set then alternate and office likely aren't set
        if($mobilenumber){
            Write-Host "   Phone Verification Methods:"
            Write-Host "     Mobile Number Enrolled: $mobilenumber" -ForegroundColor Yellow
            if($alternatephone){
                Write-Host "     Alternate Number Enrolled: $alternatephone" -ForegroundColor Yellow
            }
            if($officephone){
                Write-Host "     Office Number Enrolled: $officephone" -ForegroundColor Yellow
            }
        }
        
        Write-Host ""
        if($msAuthApps -or $SoftwareOathApps){
            Write-Host "   Authenticator Apps:"
        }
        if($msAuthApps){
            foreach($msAuthApp in $msAuthApps){
                write-host "    "$msAuthApp -ForegroundColor Yellow
                }
            }
        if($SoftwareOathApps){
            foreach($SoftwareOathApp in $SoftwareOathApps){
                write-host "    "$SoftwareOathApp -ForegroundColor Yellow
            }
        }

        Write-Host ""
        if($fidoKeys -or $msPasswordless){
            Write-Host "   Passwordless Authentication Methods:"
            if($msPasswordless){
                Write-Host "    "$msPasswordless -ForegroundColor Yellow
            }
            if($fidoKeys){
                foreach($fidoKey in $fidoKeys){
                    Write-Host "    "$fidoKey -ForegroundColor Yellow
                }
            }
        }
    }
    else{
        write-host "   $upn has no MFA enrollment." -ForegroundColor Red
    }
}

function Remove-MgMFAMethods($upn){
    $areyousure = ""
    $displayname = ""
    $displayname = (get-mguser -userid $upn).DisplayName

    $areyousure = read-host " Are you sure you want to clear MFA methods for $displayname ($upn)? (type Y to confirm)"
    write-host ""

    if($areyousure -eq "y"){
        $enrollments = get-MgUserAuthenticationMethod -UserID $upn
        if($enrollments.length -gt 1){
            foreach($enrollment in $enrollments){
                if($enrollment.ID -eq "3179e48a-750b-4051-897c-87b9720928f7"){
                    Remove-MgUserAuthenticationPhoneMethod -UserId $upn -PhoneAuthenticationMethodId 3179e48a-750b-4051-897c-87b9720928f7
                }
                if($enrollment.ID -eq "b6332ec1-7057-4abe-9331-3d72feddfe41"){
                    Remove-MgUserAuthenticationPhoneMethod -UserId $upn -PhoneAuthenticationMethodId b6332ec1-7057-4abe-9331-3d72feddfe41
                }
                if($enrollment.ID -eq "e37fc753-ff3b-4958-9484-eaa9425c82bc"){
                    Remove-MgUserAuthenticationPhoneMethod -UserId $upn -PhoneAuthenticationMethodId e37fc753-ff3b-4958-9484-eaa9425c82bc
                }
                if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"){
                    $msAuthAppID = ""
                    $msAuthAppID = $enrollment.ID
                    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $upn -MicrosoftAuthenticatorAuthenticationMethodId $msAuthAppID
                }
                if(($enrollment.AdditionalProperties)."@odata.type" -eq "#microsoft.graph.softwareOathAuthenticationMethod"){
                    $totpID = ""
                    $totpID = $enrollment.ID
                    Remove-MgUserAuthenticationSoftwareOathMethod -UserID $upn -SoftwareOathAuthenticationMethodId $totpID
                }

                # Passwordless Methods are NOT MFA methods and do not need to be removed here
                # If fido2 adoption becomes widespread we can certainly add a function to kill those tokens
                # Passwordless Authenticators via The MS Authenticator app will be automatically removed when the app is removed above
            }
        }

        Write-Host "   All methods for $upn have been cleared." -ForegroundColor Green
        Write-Host ""
        
        # confirm and output
        Write-Host "   If any methods are displayed below, wait a few seconds and check for enrolled methods again."
        Write-Host "   There may be a slight delay in removing all available methods, especially passwordless."
        # Notably, passwordless authenticators tied to the app take a second to disappear after the app is removed
        Get-MgMFAMethods $upn
        
        }
    else{
        Write-Host "   MFA reset has not been confirmed for $upn. Going back to main menu..." -ForegroundColor Yellow
        Write-Host ""
    }
}

# courtsey of https://www.bgreco.net/powershell/format-color/
# use this to make easily readable log output
function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {
	$lines = ($input | Out-String) -replace "`r", "" -split "`n"
	foreach($line in $lines) {
		$color = ''
		foreach($pattern in $Colors.Keys){
			if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
			elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
		}
		if($color) {
			Write-Host -ForegroundColor $color $line
		} else {
			Write-Host $line
		}
	}
}

function Get-MgRecentMFASignIns($upn){
    # quick brief results for all MFA attempts; does not contain useful info like client, app, IP etc
    $logresult = ""
    $filterResult = ""
    $logresult = Get-MgAuditLogSignIn -Filter "userprincipalname eq '$upn'"
    $mfalog = $logresult | where AuthenticationRequirement -eq "multiFactorAuthentication" | where ConditionalAccessStatus -ne "notApplied" | select -ExpandProperty AuthenticationDetails | where AuthenticationMethod -ne "Previously satisfied" | where AuthenticationMethod -ne "Password" | select Succeeded,AuthenticationMethod,@{Name="LocalDateTime";Expression={$_.AuthenticationStepDateTime.ToLocaltime()}},AuthenticationStepResultDetail
    $mfalog | format-color @{'True' = 'Green'; 'False' = 'Red'}

}

function Get-MgRecentAppSignIns($upn){
    # quick brief results for all recent MFA affected sign ons; does not contain detailed MFA error info
    $logresult = ""
    $filterResult = ""
    $logresult = Get-MgAuditLogSignIn -Filter "userprincipalname eq '$upn'"

    $logresult | where AuthenticationRequirement -eq "multiFactorAuthentication" | where ConditionalAccessStatus -ne "notApplied" | select appdisplayname,@{Name="LocalTime";Expression={$_.createddatetime.ToLocalTime()}},@{Name="CAStatus";Expression={$_.conditionalaccessstatus}},ipaddress,@{Name="Location";Expression={$_.Location.City + ", " + $_.Location.State + ", " + $_.Location.CountryOrRegion}},@{Name="ErrorCode";Expression={$_.Status.ErrorCode}},@{Name="FailReason";Expression={$_.Status.FailureReason}},@{Name="Status";Expression={$_.Status.AdditionalDetails}},@{Name="MFADetail";Expression={$_.MfaDetail.AuthMethod}},@{Name="Browser";Expression={$_.DeviceDetail.Browser}},@{Name="DeviceName";Expression={$_.DeviceDetail.DisplayName}},@{Name="OS";Expression={$_.DeviceDetail.OperatingSystem}} | where Status -ne "MFA requirement satisfied by claim in the token" | format-color @{'failure' = 'red'; 'success' = 'green'}

}

function Get-MgMFASignInTable($upn){
    # tries to collect and display all recent MFA affected sign ons and explode results to show individual MFA details including descriptive errors
    $logresult = ""
    $filterResult = ""
    $logresult = Get-MgAuditLogSignIn -Filter "userprincipalname eq '$upn'"
    $filtered = $logresult | where AuthenticationRequirement -eq "multiFactorAuthentication" | where ConditionalAccessStatus -ne "notApplied" | Sort-Object -Property CreatedDateTime
    foreach($log in $filtered){
    $allfields = ""
    $row1 = ""
    #$row2 = ""
    $row3 = ""
    $mfatable = ""
    $divider = "="*($host.UI.RawUI.WindowSize.Width) 
    $allfields = $log | select appdisplayname,AuthenticationDetails,@{Name="LocalTime";Expression={$_.createddatetime.ToLocalTime()}},@{Name="CAStatus";Expression={$_.conditionalaccessstatus}},ipaddress,@{Name="Location";Expression={$_.Location.City + ", " + $_.Location.State + ", " + $_.Location.CountryOrRegion}},@{Name="ErrorCode";Expression={$_.Status.ErrorCode}},@{Name="FailReason";Expression={$_.Status.FailureReason}},@{Name="Status";Expression={$_.Status.AdditionalDetails}},@{Name="MFADetail";Expression={$_.MfaDetail.AuthMethod}},@{Name="Browser";Expression={$_.DeviceDetail.Browser}},@{Name="DeviceName";Expression={$_.DeviceDetail.DisplayName}},@{Name="OS";Expression={$_.DeviceDetail.OperatingSystem}} | where Status -ne "MFA requirement satisfied by claim in the token"
    $row1 = $allfields | select appdisplayname,Browser,DeviceName,OS,LocalTime
    #$row2 = $allfields | select LocalTime,ipaddress,Location # changed the formatting to make the result more condensed
    $row3 = $allfields | select CAStatus,ErrorCode,FailReason,ipaddress,Location

    $mfaTable = $allfields | select -ExpandProperty AuthenticationDetails | where AuthenticationMethod -ne "Previously satisfied" | where AuthenticationMethod -ne "Password" | select Succeeded,AuthenticationMethod,@{Name="LocalDateTime";Expression={$_.AuthenticationStepDateTime.ToLocaltime()}},AuthenticationStepResultDetail
    
    if($allfields){
        $divider | out-host
        $row1 | ft | out-host 
        #$row2 | ft | out-host
        $row3 | ft | format-color @{'failure' = 'red'; 'success' = 'green'} | out-host
        $mfaTable | format-color @{'False' = 'red'; 'True' = 'green'} | out-host
        $divider | out-host
        }
    }
}

function Revoke-MgUserSessions($upn){
    $areyousure = ""
    $displayname = ""
    $displayname = (Get-MgUser -UserID $upn).DisplayName
    $areyousure = read-host " Are you sure you want to invalidate all refresh tokens for $displayname ($upn)? (type Y to confirm)"
    write-host ""
    if($areyousure -eq "y"){
        Revoke-MgUserSign -UserID $upn
        write-host "   Refresh tokens have been cleared. Sessions that request an access token with existing tokens will require reauthentication." -ForegroundColor Green
        write-host "   Please note that the account may still be accessed for up to an hour through current access tokens." -ForegroundColor Green
        write-host ""}
    else{
        Write-Host "   Token invalidation has not been confirmed for $upn. Going back to main menu..." -ForegroundColor Yellow
        Write-Host ""
    }
}

function Set-ScriptUser(){
    
    $upn = ""
    $upn = read-host " Enter the UserPrincipalName"

    # QOL: allows us to be lazy with UPN
    # uncomment to use; allows the set-scriptuser to autofill domain portion of upn if not provided
    <#
    $domain = ""
    $aadtenant = "[YOUR TENANT HERE].onmicrosoft.com" # for accounts without a custom domain

    if($upn -like "*@$domain"){
        # nothing
    }
    elseif($upn -like "*@$aadtenant"){
        # nothing
    }
    else{
        $upn = $upn.replace(' ','')
        $upn = $upn + "@$domain"
    }
    #>

    return $upn

    }

# Banner/init connection
Write-Host "
    =========================================
          Microsoft Graph MFA Management
    =========================================

    "

Check-MgGraphStatus



# easy repeat/clear out user inputs
function Display-Menu{
    Write-Host "

    Select a numbered option below, or 'q' to quit.

    0) Set User

    1) Get Registered MFA Methods and Details for User

    2) Clear MFA Registration for User

    3) Get Detailed Sign In Log

    4) Get MFA Usage Log Summary

    5) Get Sign In Log Summary

    6) Revoke Refresh Tokens (Require re-authentication)

    "
    $choice = 0
    $upn = ""}


$currentUser = ""
# when user wishes to exit script we'll increment $EnterScript later
while($EnterScript -eq "0")
    {

    Display-Menu

    if($currentUser){
    write-host "   The currently loaded user is: $currentUser" -ForegroundColor Green
    write-host ""}
    else{
    write-host "   No user loaded." -ForegroundColor Red
    write-host "   Please set a user via option 0." -ForegroundColor Red
    write-host ""
    }

    $choice = read-host " Selection"
    write-host ""

    # select the case based on input, quit, or fail
    if($choice -eq "0"){
        $currentUser = Set-ScriptUser
        }

    elseif($choice -eq "1"){
        $upn = $currentUser
        write-host ""

        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Get-MgMFAMethods $upn
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
        }

    elseif($choice -eq "2"){
        $upn = $currentUser

        write-host ""
        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Remove-MgMFAMethods $upn
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "3"){
        $upn = $currentUser

        write-host ""
        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Get-MgMFASignInTable $upn
            Write-Host ""
            Write-Host "   Most recent sign ins appear at the bottom of the results. Scroll up for history." -ForegroundColor Yellow
            Read-Host "      Press any key to continue..."
            Write-Host ""
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "4"){
        $upn = $currentUser

        write-host ""
        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Get-MgRecentMFASignIns $upn
            Write-Host ""
            Read-Host "Press any key to continue..."
            Write-Host ""
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "5"){
        $upn = $currentUser

        write-host ""
        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Get-MgRecentAppSignIns $upn
            Write-Host ""
            Read-Host "Press any key to continue..."
            Write-Host ""
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif($choice -eq "6"){
        $upn = $currentUser

        write-host ""
        if(get-mguser -userid $upn -ErrorAction SilentlyContinue){
            Revoke-MgUserSessions $upn
            }

        else{
            write-host " User not found. Returning to menu." -ForegroundColor Red
            }
    }

    elseif(($choice -eq "q") -or ($choice -eq "Q")){
        # when user is done increment EnterScript to kill the while loop and exit script
        $EnterScript++
        }
    else{
        #Shame on you
        write-host " Not a valid selection." -ForegroundColor Red
    }
}
