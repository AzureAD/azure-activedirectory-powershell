#requires -version 3

<#

.SYNOPSIS
	Retrieve User UPN from the provided text Input File of User Object IDs

.DESCRIPTION

	Version: 1.0.4

    - Retrieve User UPN from the provided text file of 1 unique User Object ID per line (No Headers)
    - Before running script,  establish an AzureAD Powershell connection to the targeted Azure AD tenant environment
    - An output CSV will be written to the same directory as the source input file path

    - Verify the PS session is enabled to run PS1 files based on the Execution Policy settings - For more information about Windows PowerShell execution policies, see about_Execution_Policies (http://go.microsoft.com/fwlink/?LinkID=135170).
    - Run the PS1 file with the -InputFilePath parameter with the path to the input text file
    - The default encoding for the output CSV is ASCII, but can be changed by also including the -CSVEncoding Unicode parameter

.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>
param (
    # Path to Input file with User Object ID per line
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        Position = 0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    $InputFilePath,
    # Default encoding for exported CSV is ASCII, but if using extended characters set as Unicode
    [Parameter(Mandatory = $false)]
    $CSVEncoding = "ASCII"
)
# Setting verbose preferences for this script session to emit info to screen
$oldverbose = $VerbosePreference
$verbosePreference = "continue"

# Verifying the path from Input File can be read
write-verbose "Checking path for Input Files...."
if (Test-Path -Path $InputFilePath) {
    $inputFile = get-content $InputFilePath
}
else {
    write-error ("Input File not found at $InputFilePath.  Plese check your file location and run again!")
}

#Checking for AzureAD Cmdlets installation and existing Connect-AzureAD Session that will be used for the query

$cmdletsInstalled = get-module AzureAD* -ListAvailable
if ($Null -eq $cmdletsInstalled) {
    Write-Error -ErrorAction Stop "Azure AD PowerShell Cmdlets not installed on system! -  Please visit https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0 for information on installing Cmdlets first then re-run script"
}
else {
    #checking for existing Azure AD Session

    try {

        $AzureADsession = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue

        if ($Null -eq $AzureADsession) {
            Write-error "Existing Azure AD session NOT found. Please connect to the Azure AD tenant by using the appropriate Connect-AzureAD commands for your environment and re-run the script." -ErrorAction Stop
        }
        else {
            $TenantMessage = ("Using existing Azure AD Session connection for TenantID {0} with Tenant Name {1} using Account {2}" -f $AzureADsession.TenantID, $AzureADSession.TenantDomain, $AzureADSession.Account)

            Write-Verbose $TenantMessage
        }
    }
    catch {
        Write-error "Existing Azure AD session NOT found. Please connect to the Azure AD tenant by using the appropriate Connect-AzureAD commands for your environment and re-run the script." -ErrorAction Stop

    }
}

# Output of results to be rturned
$returnedResults = @()



$inputRecordCount = $inputFile.count
$i = 1
#Processing each record in the input text file
foreach ($r in $inputFile) {


    Write-Verbose ("Querying for record {0} of {1} in Input File" -f $i++, $inputRecordCount)
    $UserID = $Null

    # Trimming line to catch for whitespaces
    $UserID = $r.Trim()


    $outputRecord = [ordered]@{}

    #Get User Details for the User ObJect ID in the Input File
    write-verbose ("Retrieving User Details for User Object ID {0}" -f $UserID)

    try {
        $AzureAdUser = $Null
        $AzureADUser = get-azureaduser -ObjectId $UserID
        Write-Verbose "`t User Found!"
        $outputRecord.'User ID' = $AzureADUser.ObjectID
        $outputRecord.'UPN' = $AzureADUser.UserPrincipalName


    }
    catch {
        Write-Verbose "`t User NOT Found!"
        $outputRecord.'User ID' = $UserID
        $outputRecord.'UPN' = "NOT FOUND"
    }


    # Adding output to output collection to be returned.
    $output = [pscustomobject]$outputRecord
    $returnedResults += $output

}



#Exporting Results in Unicode encoded CSV file with a runtime timedate in the file name in the same directory
#the source Input File was found.
$TimeStamp = (get-date -F yyyy-MM-dd_HH-mm-ss)
$CSVFileName = $InputFilePath.replace(".csv", "").replace(".txt", "") + "_UPDATED_$TimeStamp" + ".csv"
Write-Verbose "Outputting CSV Results $CSVFileName"
$returnedResults|export-csv $CSVFileName -NoTypeInformation -Encoding $CSVEncoding
Write-Verbose ("Process complete for querying Tenant {0}!!" -f $AzureADsession.TenantID)
$verbosePreference = $oldverbose
