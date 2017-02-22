#Requires –Version 5

<# 
 
.SYNOPSIS
	AzureADUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for common administrative tasks

.DESCRIPTION

	Version: 1.0.0

	AzureADUtils.psm1 is a Windows PowerShell module with some Azure AD helper functions for common administrative tasks


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>


######################
#HELPER CODE FOR ADAL
######################

$source = @" 
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Security.Cryptography.X509Certificates;

public static class AdalHelper
{
    public static string ObtainAadAccessTokenByPromptingUserCredential(string aadTokenIssuerUri, string resource, string clientId, string redirectUri)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientId: clientId, 
            redirectUri: new Uri(redirectUri),
            promptBehavior: PromptBehavior.Always,
            userId: UserIdentifier.AnyUser,
            extraQueryParameters: "nux=1"
        );

        return authenticationResult.AccessToken;
    }
         
    public static string ObtainAadAccessTokenWia(string aadTokenIssuerUri, string resource, string clientId)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        UserCredential uc = new UserCredential();
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientId: clientId,
            userCredential: uc            
        );
        return authenticationResult.AccessToken;
    }


    public static string ObtainAadAccessTokenWithCert(string aadTokenIssuerUri, X509Certificate2 cert, string resource, string clientId)
    {
        AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
        ClientAssertionCertificate certCred = new ClientAssertionCertificate(clientId, cert);
        AuthenticationResult authenticationResult = authenticationContext.AcquireToken
        (
            resource: resource,
            clientCertificate: certCred
        );
        return authenticationResult.AccessToken;
    }
}
"@

function Initialize-ActiveDirectoryAuthenticationLibrary()
{
   $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
   $modulePath = $moduleDirPath + "\AzureADUtils"

   if (Test-Path $modulePath) 
   {
      $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

      $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

      $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

      if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0)
      {
        Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
        [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly[0].FullName) | out-null
        [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
        $reqAssem = @($ADAL_Assembly[0].FullName, $ADAL_WindowsForms_Assembly.FullName)
        Add-Type -ReferencedAssemblies $reqAssem -TypeDefinition $source -Language CSharp -IgnoreWarnings
        return $true
      }
      else
      {
        Write-Host "Fixing Active Directory Authentication Library package directories ..." -ForegroundColor Yellow
        $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
        Write-Host "Not able to load ADAL assembly. Delete the Nugets folder under" $modulePath ", restart PowerShell session and try again ..."
        return $false
      }
    }
    else
    {
        Write-Host "Current module is not part of the Powershell Module path. Please run Install-AzureADUtilsModule, restart the PowerShell session and try again.." -ForegroundColor Yellow
    }
}

#Bootstrap the initialization of ADAL
Initialize-ActiveDirectoryAuthenticationLibrary

<# 
 .Synopsis
  Gets an access token based on a confidential client credential

 .Description
  This function returns a string with the access token for the Azure AD Graph API.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientCredential
  A Powershell Credential with UserName=ClientID, Password=Application Key


 .Example
   $accessToken = Get-AzureADGraphAPIAccessTokenFromAppKey -TenantDomain "contoso.com" -ClientCredential (Get-Credential)
#>
Function Get-AzureADGraphAPIAccessTokenFromAppKey
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,        
        [Parameter(Mandatory=$true)]
        [pscredential]
        $ClientCredential            # Credential object that captures the client credentials
    )

    $ClientID = $ClientCredential.UserName                    
    $ClientSecret = $ClientCredential.GetNetworkCredential().Password         

    if ([String]::IsNullOrWhiteSpace($ClientID))
    {
        throw "Client ID is missing"
    }

    if ([String]::IsNullOrWhiteSpace($ClientSecret))
    {
        throw "Client secret is missing"
    }

    $loginURL = "https://login.windows.net"

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$TenantDomain/oauth2/token?api-version=1.0 -Body $body

    if ($oauth.access_token -eq $null) 
    {
        throw "ERROR: No Access Token"
    }

    Write-Output $oauth.access_token

}

<# 
 .Synopsis
  Gets an access token based on a user credential using web authentication to access the Azure AD Graph API.

 .Description
  This function returns a string with the access token from a user. This will pop up a web authentication prompt for a user

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientId
  The client ID of the application you want the token for
  
 .Parameter Redirect URI
  Redirect URI for the OAuth request
  

 .Example
   $accessToken = Get-AzureADGraphAPIAccessTokenFromUser -TenantDomain "contoso.com"
#>
Function Get-AzureADGraphAPIAccessTokenFromUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true, ParameterSetName="PromptUserCredential")]
        [string]
        $RedirectUri,
        [Parameter(ParameterSetName="WIA")]
        [switch]
        $WindowsAuthentication

    )
    if ($WindowsAuthentication)
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenWia("https://login.windows.net/$TenantDomain/", "https://graph.windows.net/", $ClientId);
        Write-Output $AadToken
    }
    else
    {
        $AadToken = [AdalHelper]::ObtainAadAccessTokenByPromptingUserCredential("https://login.windows.net/$TenantDomain/", "https://graph.windows.net/", $ClientId, $RedirectUri);
        Write-Output $AadToken
    }
}


<# 
 .Synopsis
  Gets an access token based on a certificate credential

 .Description
  This function returns a string with the access token from a certificate credential to access the Azure AD Graph API.  

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter ClientID
  The client ID of the application that has the certificate

 .Parameter Certificate
  The X509Certificate2 certificate. The private key of the certificate should be accessible to obtain the access token
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-AzureADGraphAPIAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
#>
Function Get-AzureADGraphAPIAccessTokenFromCert
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,
        [Parameter(Mandatory=$true)]
        [string]
        $ClientId,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    $AadToken = [AdalHelper]::ObtainAadAccessTokenWithCert("https://login.windows.net/$TenantDomain/", $Certificate, "https://graph.windows.net/", $ClientId);
    Write-Output $AadToken
}


<# 
 .Synopsis
  Performs a query against Azure AD Graph API.

 .Description
  This functions invokes the Azure AD Graph API and returns the results as objects in the pipeline. This function also traverses all pages of the query, if needed.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter AccessToken
  Access token for Azure AD Graph API

 .Parameter GraphQuery
  The Query against Graph API
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-AzureADGraphAPIAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
  $SignInLog = Invoke-AzureADGraphAPIQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "/activities/signinEvents?api-version=beta" 
#>
Function Invoke-AzureADGraphAPIQuery
{
    [CmdletBinding()]
    param
    (
       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain, # For example, contoso.onmicrosoft.com    
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken, # For example, contoso.onmicrosoft.com,        
        [string]
        $GraphQuery
    )

    Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Invoking Graph API"

    $headerParams  = @{'Authorization'="Bearer $AccessToken"}
       
    $queryResults = @()
    $originalUrl = "https://graph.windows.net/$TenantDomain/$GraphQuery"
    $queryUrl = "https://graph.windows.net/$TenantDomain/$GraphQuery"
    $queryCount = 0

    while (-not [String]::IsNullOrEmpty($queryUrl))
    {
        $batchResult = (Invoke-WebRequest -Headers $headerParams -Uri $queryUrl).Content | ConvertFrom-Json
        if ($batchResult.value -ne $null)
        {
            $queryResults += $batchResult.value
        }
        else
        {
            $queryResults += $batchResult
        }
        $queryCount = $queryResults.Count
        Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Retrieving results ($queryCount found so far)" 
        $queryUrl = ""

        $odataNextLink = $batchResult | Select-Object -ExpandProperty "@odata.nextLink" -ErrorAction SilentlyContinue

        if ($odataNextLink -ne $null)
        {
            $queryUrl =  $odataNextLink
        }
        else
        {
            $odataNextLink = $batchResult | Select-Object -ExpandProperty "odata.nextLink" -ErrorAction SilentlyContinue
            if ($odataNextLink -ne $null)
            {
                $absoluteUri = [Uri]"https://bogus/$odataNextLink"
                $skipToken = $absoluteUri.Query.TrimStart("?")
                $queryUrl = "$originalUrl&$skipToken"
            }
        }
    }

    Write-Progress -Id 1 -Activity "Querying directory" -Completed

    Write-Output $queryResults
}

<# 
 .Synopsis
  Generates a Report of all assignments to applications.

 .Description
  This function queries all the applications, and for each one, obtain the list of role assignments.

 .Parameter TenantDomain
  The domain name of the tenant you want the token for.

 .Parameter AccessToken
  Access token for Azure AD Graph API

  
 .Example
  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2
  $AccessToken = Get-AzureADGraphAPIAccessTokenFromCert  -TenantDomain "contoso.com" -ClientId $ReportingClientId -Certificate $Cert
  $SignInLog = Invoke-AzureADAppAssignmentReport -AccessToken $AccessToken -TenantDomain $TenantDomain 
#>
Function Get-AzureADAppAssignmentReport
{    
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken           
    )
    
    Write-Progress -Id 10 -Activity "Building app assignment report" -CurrentOperation "Getting list of applications" 


    $apps = Invoke-AzureADGraphAPIQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "servicePrincipals?api-version=1.5"

    $results = @()
    $appCount = $apps.Count
    $appIndex = 1

    foreach($app in $apps)
    {
        Write-Progress -Id 10 -Activity "Building app assignment report" -PercentComplete (100 * $appIndex / $appCount)  -CurrentOperation "Extracting permissions for each application ($appIndex/$appCount)"  

        $appObjectId = $app.objectId
        $appRoles = Invoke-AzureADGraphAPIQuery -AccessToken $AccessToken -TenantDomain $TenantDomain -GraphQuery "servicePrincipals/$appObjectId/appRoleAssignedTo?api-version=1.5"
        foreach($appPermission in $appRoles)
        {
            $result = New-Object -TypeName PSObject
	        $result | add-member -MemberType NoteProperty -name "appObjectId" -value $app.objectId
            $result | add-member -MemberType NoteProperty -name "appDisplayName" -value $app.appDisplayName
            $result | add-member -MemberType NoteProperty -name "principalId" -value $appPermission.principalId
            $result | add-member -MemberType NoteProperty -name "principalDisplayName" -value $appPermission.principalDisplayName
            $result | add-member -MemberType NoteProperty -name "principalType" -value $appPermission.principalType
            $results += $result
        }
        $appIndex++
    }

    Write-Progress -Id 10 -Activity "Building app assignment report" -Completed

    Write-Output $results
}

function Join($k, $l, $r) {
    [pscustomobject]@{
        Key    = $k
        Left   = $l
        Right  = $r
    }
}


#Example adapted from: https://gist.githubusercontent.com/mlanza/d1a732df9b7519dd13b4/raw/9e2c53508d279ef6d2bf8cab1b8c9dd74541e8a4/Join-Object.ps1

function Join-Object
{
    #EXAMPLE: Join-Object -left (Import-Csv $users) -leftKey { $_.Surname + ", " + $_.GivenName } -right (Import-Csv $dcas) -rightKey { $_."Last Name" + ", " + $_."First Name" }
    Param(
        $left,    #a table of data, possibily read from a csv
        $leftKey, #a block that returns a value on which to match
        $right,   #a table of data, possibily read from a csv
        $rightKey #a block that returns a value on which to match
    )


    $l = $left  | Group $leftKey  -AsHashTable -AsString
    $r = $right | Group $rightKey -AsHashTable -AsString

    $l.Keys | ? {  $r.ContainsKey($_) } | % { Join $_ $l."$_" $r."$_" }
    $l.Keys | ? { !$r.ContainsKey($_) } | % { Join $_ $l."$_" $null   }
    $r.Keys | ? { !$l.ContainsKey($_) } | % { Join $_ $null   $r."$_" }
}

Function Get-AzureADAppStaleLicensingReport
{
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain,  
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken,
        [Parameter(Mandatory=$true)]
        [Int]
        $CutOffDays
    )
    $CutOffDateFilter = "{0:s}Z" -f (Get-Date).AddDays(-1 * $CutOffDays)
   
    #Step 1: Get all sign ins from all folks
    $signInActivity = Invoke-AzureADGraphAPIQuery -TenantDomain $TenantDomain -AccessToken $AccessToken -GraphQuery "/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $CutOffDateFilter"

    #Step 2: Get all users
    $allUsers = Get-AzureADUser -Top 1000000

    #Step 3: Join both

    $joinedSet = Join-Object -left $allUsers -right $signInActivity -leftKey {$_.userPrincipalName} -rightKey {$_.userPrincipalName}

    #Step 4: Return the UPNs of the guys who have not logged in 

    $staleUsers = $joinedSet | Where {$_.Right -eq $null}

    $TenantSKUs = Get-AzureADSubscribedSku

    foreach($staleUser in $staleUsers)
    {
        $userUPN = $staleUser.Key
        $userSkus = $staleUser.Left.AssignedLicenses
        
        if ($userSkus -ne $null)
        {

            $skuString = ""

            foreach ($userSku in $userSkus)
            {
                $skuName = $TenantSKUs | where {$_.SkuId -eq $userSku.SkuId} | Select-Object -ExpandProperty SkuPartNumber
                $skuString +=  $skuName + ";"

            }

            $staleUserInfo = New-Object PSObject
            $staleUserInfo  | Add-Member -MemberType NoteProperty -Name "UPN" -Value $staleUser.Key
            $staleUserInfo  | Add-Member -MemberType NoteProperty -Name "SKUs" -Value $SkuString
        
            Write-Output $staleUserInfo
        }
    }


}

<# 
 .Synopsis
  Adds certificate Credentials to an application 

 .Description
  This functions installs a client certificate credentials 

 .Parameter ApplicationObjectId
  The application Object ID that will be associated to the certificate credential
  
 .Example

  $ReportingClientId = "9a0112fb-6626-4761-a96b-a5f433c69ef7"
  $Cert = dir Cert:\LocalMachine\my\0EA8A7037A584C3C7BB54119D754DE1024AABAB2

  New-AzureADApplicationCertificateCredential -ApplicationObjectId $ReportingClientId -Certificate $Cert
  
#>

Function New-AzureADApplicationCertificateCredential
{
  param
  (
        [Parameter(Mandatory=$true)]
        [string]
        $ApplicationObjectId,
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
  )

    $bin = $Certificate.GetRawCertData()
    $base64Value = [System.Convert]::ToBase64String($bin)
    $thumbprint = $Certificate.GetCertHash()
    $base64Thumbprint = [System.Convert]::ToBase64String($thumbprint)

    New-AzureADApplicationKeyCredential `
        -ObjectId $ApplicationObjectId `
        -CustomKeyIdentifier $base64Thumbprint `
        -Type AsymmetricX509Cert `
        -Usage Verify `
        -Value $base64Value #`
        #-StartDate $Certificate.GetEffectiveDateString() `
        #-EndDate $Certificate.GetExpirationDateString()
}


<# 
 .Synopsis
  Removes all on premises synchronized users from a tenant

 .Description
  Removes all on premises synchronized users from a tenant. This cmdlet requires the Azure AD Powershell Module

 .Parameter Force
  When this parameter is set, then the confirmation message is not shown to the user.

 .Example
  Connect-MSOLService
  Remove-AzureADOnPremUsers -Force
#>
Function Remove-AzureADOnPremUsers
{
    [CmdletBinding()]
    param
    (   
       [Switch]
       $Force    
    )    

    $Proceed = $Force

    if (-not $Force)
    {
        $title = "Remove Synchronized Accounts"
        $message = "This will remove ALL on-premises synchronized users from your tenant. Do you want to proceed"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Remove all synchronized user accounts from Azure AD. You will need to execute a full sync cycle"

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Keep all the objects on premises."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

        if ($result -eq 0)
        {
            $Proceed = $true
        }
    }

    if ($Proceed)
    {

        Write-Progress -Id 10 -Activity "Removing On-Premises users from your tenant..." -CurrentOperation "Connecting to Azure AD" 
        Connect-MsolService
        Write-Progress -Id 10 -Activity "Removing On-Premises users from your tenant..." -CurrentOperation "Removing users the cloud" 
        $UsersToRemove = Get-MsolUser -Synchronized | Where {$_.UserPrincipalName -notlike "Sync*"}
        $UsersToRemove | %{Remove-MsolUser -ObjectId $_.ObjectId -Force }
        Get-MsolUser -ReturnDeletedUsers | %{ Remove-MsolUser -ObjectId $_.ObjectId -RemoveFromRecycleBin -Force }        
        $UsersCount = $UsersToRemove | Measure-Object  | Select-Object -ExpandProperty Count
        "$UsersCount have been deleted from the tenant. To Resynchronize, clean the Azure AD Connect connector spaces and force an Initial Sync Cycle"
    }
}

<# 
 .Synopsis
  Installs this Powershell Module in the Powershell module path, downloading and copying the right dependencies 

 .Description
  This cmdlet copies the module in the module path, and downloads the ADAL library using Nuget

 .Example
  Install-AzureADUtilsModule

#>
function Install-AzureADUtilsModule
{
    [CmdletBinding()]
    param()

    $myDocumentsModuleFolderIsInPSModulePath = $false
    [Environment]::GetEnvironmentVariable("PSModulePath") -Split ';' | % {
      if ($_.ToLower() -eq ([Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules").ToLower()){
        $myDocumentsModuleFolderIsInPSModulePath = $true
      }
    }

    if(-not $myDocumentsModuleFolderIsInPSModulePath){
      $newPSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath") + ";" + [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules";
      [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "Process")
      [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "User")

    }


    $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
    $modulePath = $moduleDirPath + "\AzureADUtils"

    if (Test-Path $modulePath)
    {
        Write-Host "Removing existing module directory under "$moduleDirPath -ForegroundColor Green
        Remove-Item -Path $modulePath -Recurse -Force | Out-Null
    }

    Write-Host "Creating module directory under "$moduleDirPath -ForegroundColor Green
    New-Item -Path $modulePath -Type "Directory" -Force | Out-Null
    New-Item -Path $modulePath"\Nugets" -Type "Directory" -Force | Out-Null
    New-Item -Path $modulePath"\Cmdlets" -Type "Directory" -Force | Out-Null


  if(-not (Test-Path ($modulePath+"\Nugets"))) {New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null}

  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

  if($adalPackageDirectories.Length -eq 0){
    Write-Host "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." -ForegroundColor Yellow
    if(-not(Test-Path ($modulePath + "\Nugets\nuget.exe")))
    {
      Write-Host "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." -ForegroundColor Yellow
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
    }

    $nugetUpdateExpression = $modulePath + "\Nugets\nuget.exe update -self"
    Invoke-Expression $nugetUpdateExpression

    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.14.201151115 -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression $nugetDownloadExpression

  }

    Copy-Item "$PSScriptRoot\AzureADUtils.psm1" -Destination $modulePath -Force

    Import-Module AzureADUtils
    Get-Command -Module AzureADUtils

}

Export-ModuleMember Install-AzureADUtilsModule
Export-ModuleMember New-AzureADApplicationCertificateCredential
Export-ModuleMember Get-AzureADGraphAPIAccessTokenFromAppKey
Export-ModuleMember Get-AzureADGraphAPIAccessTokenFromUser
Export-ModuleMember Get-AzureADGraphAPIAccessTokenFromCert
Export-ModuleMember Invoke-AzureADGraphAPIQuery
Export-ModuleMember Get-AzureADAppAssignmentReport
Export-ModuleMember Remove-AzureADOnPremUsers
Export-ModuleMember Get-AzureADAppStaleLicensingReport