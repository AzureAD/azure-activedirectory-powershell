#Requires –Version 4

<# 
 
.SYNOPSIS
	Contains data gathering, health checks, and additional utilities for AD FS server deployments.

.DESCRIPTION

	Version: 1.0.0

	GTPUtils.psm1 is a Windows PowerShell module with some helper functions common in customer questions


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
    public static string ObtainAadAccessTokenByPromptingUserCredential(string aadTokenIssuerUri)
        {
            AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
            AuthenticationResult authenticationResult = authenticationContext.AcquireToken
            (
                resource: "https://graph.windows.net/",
                clientId: "cf6d7e68-f018-4e0a-a7b3-126e053fb88d",
                redirectUri: new Uri("urn:ietf:wg:oauth:2.0:oob"),
                promptBehavior: PromptBehavior.Always,
                userId: UserIdentifier.AnyUser,
                extraQueryParameters: "nux=1"
            );

            return authenticationResult.AccessToken;
         }
         
    public static string ObtainAadAccessTokenSilent(string aadTokenIssuerUri, string username, SecureString password)
        {
            AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
            ClientCredential cc = new ClientCredential(username, password);
            AuthenticationResult authenticationResult = authenticationContext.AcquireTokenSilent
            (
                resource: "https://graph.windows.net/",
                clientCredential: cc,
                userId: UserIdentifier.AnyUser
            );
            return authenticationResult.AccessToken;
        }


    public static string ObtainAadAccessTokenWithCert(string aadTokenIssuerUri, string clientId, X509Certificate2 cert)
        {
            AuthenticationContext authenticationContext = new AuthenticationContext(aadTokenIssuerUri);
            ClientAssertionCertificate certCred = new ClientAssertionCertificate(clientId, cert);
            AuthenticationResult authenticationResult = authenticationContext.AcquireToken
            (
                resource: "https://graph.windows.net/",
                clientCertificate: certCred
            );
            return authenticationResult.AccessToken;
        }


}
"@

function Initialize-ActiveDirectoryAuthenticationLibrary(){
   $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
   $modulePath = $moduleDirPath + "\AzureADUtils"

  

  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

  $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

  $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)

  if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
    Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
    [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly[0].FullName) | out-null
    [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
    $reqAssem = @($ADAL_Assembly[0].FullName, $ADAL_WindowsForms_Assembly.FullName)

    Add-Type -ReferencedAssemblies $reqAssem -TypeDefinition $source -Language CSharp -IgnoreWarnings

    return $true
  }

  else{
    Write-Host "Fixing Active Directory Authentication Library package directories ..." -ForegroundColor Yellow
    $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
    Write-Host "Not able to load ADAL assembly. Delete the Nugets folder under" $modulePath ", restart PowerShell session and try again ..."
    return $false
  }
}

##Bootstrap the call
Initialize-ActiveDirectoryAuthenticationLibrary

Function Get-AzureADCertificateManifestInfo
{
    [CmdletBinding()]
    param
    (  
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $certBinaryInfo = $Certificate.GetRawCertData()
    $certB64Info = [System.Convert]::ToBase64String($certBinaryInfo)
    $certThumbprint = $Certificate.Thumbprint
    $keyId = [System.Guid]::NewGuid().ToString()

    $result = New-Object -TypeName PSObject -Property @{
        customKeyIdentifier = $certThumbprint
        keyId = $keyId
        type = "AsymmetricX509Cert"
        usage = "Verify"
        value = $certB64Info
    }

    Write-Output $result

}

Function Get-AzureADAcessTokenFromConfidentialClient
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

Function Get-AzureADAccessTokenFromUser
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain
    )
    $AadToken = [AdalHelper]::ObtainAadAccessTokenByPromptingUserCredential("https://login.windows.net/$TenantDomain/");
    Write-Output $AadToken
}

Function Get-AzureADAccessTokenFromCert
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
    $AadToken = [AdalHelper]::ObtainAadAccessTokenWithCert("https://login.windows.net/$TenantDomain/", $ClientId, $Certificate);
    Write-Output $AadToken
}

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
        $queryUrl = $batchResult | Select-Object -ExpandProperty "@odata.nextLink" -ErrorAction SilentlyContinue
    }

    Write-Progress -Id 1 -Activity "Querying directory" -Completed

    Write-Output $queryResults
}

Function Get-AzureADAppAssignmentQuery
{    
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory=$true)]
        [string]
        $TenantDomain, # For example, contoso.onmicrosoft.com    
        [Parameter(Mandatory=$true)]
        [string]
        $AccessToken # For example, contoso.onmicrosoft.com,           
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




Export-ModuleMember Invoke-AzureADGraphAPIQuery
Export-ModuleMember Get-AzureADAcessTokenFromConfidentialClient
Export-ModuleMember Get-AzureADAppAssignmentQuery
Export-ModuleMember Remove-AzureADOnPremUsers
Export-ModuleMember Install-AzureADUtilsModule
Export-ModuleMember Get-AzureADAccessTokenFromUser
Export-ModuleMember Get-AzureADAccessTokenFromCert
Export-ModuleMember Get-AzureADCertificateManifestInfo