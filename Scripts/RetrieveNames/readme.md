


## Step 1: Create Text File with Impacted Users
For your security, we are not including human readable names in the Message Center or e-mail notifications. To retrieve the user information in a human readable format, please copy and paste the userIds posted in the Message Center or in the notification e-mail into a text editor and save the text file as "ImpactedUsers.txt". Note the file path when you save the text file, as you will need it for Step 3. 

>**Note:** Your Message Center notification may instruct you to contact Microsoft Support to receive the list of impacted userIds for your tenant. If so, download the text file that Microsoft Support provides and save the file as "ImpactedUsers.txt"


## Step 2: Download the PowerShell Script
You will use a PowerShell script to retrieve the UPNs. [Download the PowerShell script here](https://github.com/AzureAD/azure-activedirectory-powershell/tree/gh-pages/Scripts/RetrieveNames/RetrieveNames.ps1
). To download the PowerShell script, you can copy and paste the text from the aforementioned link into a text file and save it as a .ps1 file.

>**Note:** Make sure that you have the AzureAD cmdlets installed. If you do not already have them installed, you can install them here: [Azure AD PowerShell for Graph](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0). 

## Step 3: Connect to Azure AD PowerShell
Before you can run the script, you must first connect to Azure AD. 
```
Connect-AzureAD
```

To connect to a specific environment of Azure Active Directory (such as "AzureGermanyCloud"), use the AzureEnvironment parameter, as follows:

```
Connect-AzureAD -AzureEnvironment "<your Azure Environment>"
```
This example connects your PowerShell session to the German AzureAD environment.

## Step 4: Run the PowerShell Script
Run the PowerShell script you downloaded in step 2, making sure to specify the text file path. This script will output a CSV file with the impacted users' UPNs.

>**Note:** You may need to allow the downloaded script to run on your workstation by [unblocking downloaded PowerShell scripts](https://social.technet.microsoft.com/wiki/contents/articles/38496.unblock-downloaded-powershell-scripts.aspx).

```
.\RetrieveUsers.ps1 -InputFilePath <path to your text file>
```
