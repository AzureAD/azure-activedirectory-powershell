$userInput = Read-Host "This tool will delete the preview version of the Pass-through Authentication Agent. Type 'q' to abort or press enter to continue:"

if($userInput -ne 'q')
{
    $previewPassthroughAuthenticationAgentNames = @("Microsoft Azure AD Application Proxy Connector", "Microsoft Azure Active Directory Application Proxy Connector")
    $previewPassthroughAuthenticationAgentUpdaterNames = @("Microsoft Azure AD Application Proxy Connector Updater", "Microsoft Azure Active Directory Application Proxy Connector Updater")
    $isAgentInstalled = $false;
    $isAgentUpdaterInstalled = $false;
    $installedAgent = "";

    # This will loop through all the old MSIs and checks if the agent with pass-through authentication feature is installed 
    $installedPrograms = (get-wmiobject Win32_Product)
    $installedAgentProductCode = ""
    $installedAgentUpdaterProductCode = ""
    Write-Host "Searching for the preview versions of the Pass-through authentication agents before uninstalling them. This might take a few seconds..."
    foreach($installedProgram in $installedPrograms)
    {
        if( ($previewPassthroughAuthenticationAgentNames.Contains($installedProgram.Name)) )
        {
            # Check the feature name to make sure that it is pass-through authentication
            $installedAgent = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft AAD App Proxy Connector" -Name ConnectorFeature).ConnectorFeature
            $isAgentInstalled = $true
            $installedAgentProductCode = $installedProgram.IdentifyingNumber
        }

        if( ($previewPassthroughAuthenticationAgentUpdaterNames.Contains($installedProgram.Name)) )
        {
            $isAgentUpdaterInstalled = $true;
            $installedAgentUpdaterProductCode = $installedProgram.IdentifyingNumber
        }

        if($isAgentInstalled -and $isAgentUpdaterInstalled)
        {
            break
        }
    }

    # Check if the preview version of pass-through authentication agent is installed
    if( $isAgentInstalled -and $installedAgent -eq "PassthroughAuthentication" )
    {
        Write-Host ("Uninstalling the Preview Version of Pass-through authentication agent")
        & cmd.exe /C "msiexec /x $installedAgentProductCode /quiet"
        if($LASTEXITCODE -eq 0)
        {
            Write-Host ("Successfully uninstalled the preview version of Pass-through authentication agent") -f Green
        }
        else
        {
            Write-Host ("The preview version of pass-through authentication agent may not have been successfully uninstalled. Exit Code: '{0}'" -f $LASTEXITCODE) -f Red
        }

        #uninstalling the Pass-through authentication agent auto-updater
        if($isAgentUpdaterInstalled)
        {
            Write-Host ("Uninstalling the Preview Version of Pass-through authentication agent updater")
            & cmd.exe /C "msiexec /x $installedAgentUpdaterProductCode /quiet"
            if($LASTEXITCODE -eq 0)
            {
                Write-Host ("Successfully uninstalled the Preview Version of Pass-through authentication agent updater") -f Green
            }
            else
            {
                Write-Host ("The preview version of pass-through authentication agent updater may not have been successfully uninstalled. Exit Code: '{0}'" -f $LASTEXITCODE) -f Red
            }
        }

        #Uninstalling the Agent Package from the package cache by looking up the upgrade code from the registry
        $previewPTAgentUpgradeCode = "{781F8332-277B-45BF-A5F4-AF5A117FFA73}"
        $registryUninstallationPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        $isPackageUninstalled = $false;
        foreach($registryUninstallationPath in $registryUninstallationPaths)
        {
            $registryKeys = ((Get-ChildItem -Path $registryUninstallationPath) | ForEach-Object {Get-ItemProperty $_.pspath})
            foreach($registryKey in $registryKeys)
            {
                if($registryKey.BundleUpgradeCode -eq $previewPTAgentUpgradeCode)
                {
                    Write-Host ("Uninstalling the preview version of Pass-through Authentication Package")
                    & cmd.exe /C $registryKey.QuietUninstallString
                    if($LASTEXITCODE -eq 0)
                    {
                        Write-Host ("Successfully uninstalled the preview version of Pass-through Authentication Package") -f Green
                    }
                    else
                    {
                        Write-Host ("Uninstallation of Pass-through authentication package failed with exit code: '{0}'" -f $LASTEXITCODE) -f Red
                    }
                    
                    $isPackageUninstalled = $true;
                    break
                }
            }
        }

        if(!$isPackageUninstalled)
        {
            Write-Host ("The preview version of Pass-through Authentication agent package with upgrade code '{0}' wasn't found on this machine." -f $previewPTAgentUpgradeCode) -f Yellow
        }
    }
    else
    {
        Write-Host ("Pass-through Authentication agent wasn't found on this machine.") -f Yellow
    }
}
else
{
    Write-Host ("Aborted uninstalling the preview version of Pass-through authentication agents") -f Yellow
}
# SIG # Begin signature block
# MIITKwYJKoZIhvcNAQcCoIITHDCCExgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjN1O3zsq5r9hmNOIeuNnEXS+
# HlWggg54MIIDojCCAoqgAwIBAgIQtp2hdI0V7rtJbbYCtDBOcjANBgkqhkiG9w0B
# AQ0FADBEMRIwEAYDVQQKEwlNaWNyb3NvZnQxDjAMBgNVBAsTBUF6dXJlMR4wHAYD
# VQQDExVBenVyZUVuZ0J1aWxkQ29kZVNpZ24wHhcNMTYxMjIxMTk0NDE1WhcNMTcx
# MjIxMTk0NDE0WjBEMRIwEAYDVQQKEwlNaWNyb3NvZnQxDjAMBgNVBAsTBUF6dXJl
# MR4wHAYDVQQDExVBenVyZUVuZ0J1aWxkQ29kZVNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCpOoO9r8NvhZul9uip81YwvT6TZhYa0VR0klpj9uZv
# JxsVH0beQ9W9kIBk3Dww01pyV2ToBeYsP9ogsNf7ud0hULrwSc7T89WwW+9SLo9m
# 3d/rmb1xkUwvMMCRHWmYwUUbQThF8RL38KwPsvJd2p5NLjWzFuIBjBf5pu0pCzc/
# 662+cG3uICJdvL1f7RPKMZa9GNAgKy2ss0fbONMn+S9JB7m961o2KJurCNk6mArU
# uGI5SQZcTi052eMD8E+gsfRElgkmUN8Z/UYAZf3y8+oiO9x5NOFBaVwMnRDsDOfu
# W3brVYWarZz2sJt+chqSFI/GsBqmKO9zFoV+1mzl7fORAgMBAAGjgY8wgYwwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwdQYDVR0BBG4wbIAQE+w1AYhozjTPaRBEpDDLrKFG
# MEQxEjAQBgNVBAoTCU1pY3Jvc29mdDEOMAwGA1UECxMFQXp1cmUxHjAcBgNVBAMT
# FUF6dXJlRW5nQnVpbGRDb2RlU2lnboIQtp2hdI0V7rtJbbYCtDBOcjANBgkqhkiG
# 9w0BAQ0FAAOCAQEAUB6vvTlH1LJXfx2vN39bT7jU3EBxn4UzYDHLCbVYMi45OzO8
# QZShvrhy+SbSxld/7rh9dfds89SEBGZVT5lDHUQ6pRPVHMJ3luJZbQjy8YqhwzGa
# LZ3n0qH8li8545fcgVjTut5QOwK+uRt2Xtyr+gCmHqUDojQsPRmRrUzST2PG6KJt
# wEBhunQyVkG72jeH1lP/seL05ahHtUM94H8RxqthkdETErZduRKVtAzlX//CK+Kx
# V74BZyztbXEk+/bJws+aCReklsGmBKwymehW+XASdIU/doK2eOp7yiht8mL5PGhd
# iOa7TMKv/OkE4LCGwgOv4GxgLnTXjhBMbx77rDCCBMMwggOroAMCAQICEzMAAAC1
# rH1th2smEUcAAAAAALUwDQYJKoZIhvcNAQEFBQAwdzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBMB4XDTE2MDkwNzE3NTg0NFoXDTE4MDkwNzE3NTg0NFowgbMxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAl
# BgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpCOEVDLTMwQTQtNzE0NDElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAKV8M9o+5Nqw5dkDvXss9alJtxcqg+3ZLGz+TNzQjqv4/eb6
# TnhxtsNEtUsjZjfFRKo4h0nqKTuW/lWziG6aqhvT8n8g3NFncyIpbn2TrsMmSNeY
# SN7kYGe/BP3G5Y11FuTHu+YxhhDpaxnpONXjshkVMZHoxWqapIhwi8R0jBxKT3U/
# ecpT4bi8+watNX7EEm3JQ6EMntxMzmBZanBTGG97OtbIhG6byoH9KnEIz8wId77M
# kl6s3ni3Nys7LO+BPRw3bkBjtWWU2RWnS+G88JYFYbsduQ2a9M6sm2SAYsvPyfaM
# igotjrli6sX/mIElqdGDGPZLbysBq1Vu1vP1CVcCAwEAAaOCAQkwggEFMB0GA1Ud
# DgQWBBSDHeogNPN28xh0k9pNjukepV58hTAfBgNVHSMEGDAWgBQjNPjZUkZwCu1A
# +3b7syuwwzWzDzBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLm1pY3Jvc29m
# dC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNyb3NvZnRUaW1lU3RhbXBQQ0EuY3Js
# MFgGCCsGAQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRUaW1lU3RhbXBQQ0EuY3J0MBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBQUAA4IBAQAHs/r8SVoA7IDLaLjC
# ylHG7fs0W13MVpth5k1O64SFVcodhCBUuXm1ZJ0hrCqEdf8ZRJpzKN3x7b1mg0aP
# 9qlyINYzJzkKdXeMKhYfYSn5w3gkAPbQpzPAv5mLt2sV8SpssSVwzptjKnKGfQgZ
# ZpPeqP4c1fUFqOXPmPeI+6hGKRkTxugHaqHPxzcZ3HtyJNGZaWw/E25myIwzkcUN
# yY259wBlwUPrJrCJ8Fhc7rdhMKRjwtsVoS41y3cyUXiDNYHod6DP8LYuM2eMO4a+
# Ar3nTJ1NvTpHJ6MjBFAEJ2Xwez7F5mnSsZ5JbCQrK9VDru4P58F+f5nMO0fRt0Ur
# 6yNBMIIGBzCCA++gAwIBAgIKYRZoNAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMw
# EQYKCZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0w
# KwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcN
# MDcwNDAzMTI1MzA5WhcNMjEwNDAzMTMwMzA5WjB3MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfoWyx39tIkip8
# ay4Z4b3i48WZUSNQrc7dGE4kD+7Rp9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr
# 6Hu97IkHD/cOBJjwicwfyzMkh53y9GccLPx754gd6udOo6HBI1PKjfpFzwnQXq/Q
# sEIEovmmbJNn1yjcRlOwhtDlKEYuJ6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7Po
# IZd++NIT8wi3U21StEWQn0gASkdmEScpZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4B
# mh1QCIUAEDBG7bfeI0a7xC1Un68eeEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/
# +QXDwiALAgMBAAGjggGrMIIBpzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQj
# NPjZUkZwCu1A+3b7syuwwzWzDzALBgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMC
# AQAwgZgGA1UdIwSBkDCBjYAUDqyCYEBWJ5flJRP8KuEKU5VZ5KShY6RhMF8xEzAR
# BgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTAr
# BgNVBAMTJE1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIQea0W
# oUqgpa1Mc1j0BxMuZTBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmww
# VAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAgEAEJeKw1wDRDbd6bStd9vOeVFN
# AbEudHFbbQwTq86+e4+4LtQSooxtYrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt4
# 8ovQ7DsB7uK+jwoFyI1I4vBTFd1Pq5Lk541q1YDB5pTyBi+FA+mRKiQicPv2/OR4
# mS4N9wficLwYTp2OawpylbihOZxnLcVRDupiXD8WmIsgP+IHGjL5zDFKdjE9K3IL
# yOpwPf+FChPfwgphjvDXuBfrTot/xTUrXqO/67x9C0J71FNyIe4wyrt4ZVxbARcK
# FA7S2hSY9Ty5ZlizLS/n+YWGzFFW6J1wlGysOUzU9nm/qhh6YinvopspNAZ3GmLJ
# PR5tH4LwC8csu89Ds+X57H2146SodDW4TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8if
# Qv+AeSGAnhUwZuhCEl4ayJ4iIdBD6Svpu/RIzCzU2DKATCYqSCRfWupW76bemZ3K
# Om+9gSd0BhHudiG/m4LBJ1S2sWo9iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJ
# Zr2dHYcSZAI9La9Zj7jkIeW1sMpjtHhUBdRBLlCslLCleKuzoJZ1GtmShxN1Ii8y
# qAhuoFuMJb+g74TKIdbrHk/Jmu5J4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0b
# odj6L54/LlUWa8kTo/0xggQdMIIEGQIBATBYMEQxEjAQBgNVBAoTCU1pY3Jvc29m
# dDEOMAwGA1UECxMFQXp1cmUxHjAcBgNVBAMTFUF6dXJlRW5nQnVpbGRDb2RlU2ln
# bgIQtp2hdI0V7rtJbbYCtDBOcjAJBgUrDgMCGgUAoHAwEAYKKwYBBAGCNwIBDDEC
# MAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFH9Bj+cfsuSHNBUxhOhrw6jAl4Sj
# MA0GCSqGSIb3DQEBAQUABIIBAFL52ESgGEqJ6JWeF0CiuNZ43QNR3Hk0xZZ99xbC
# NUmXN3/rQST/CwtLeiGFjM7IvagJ2H5nsE9ipAYIVcUhl4+2yAyc0eiQoodDqwYd
# LvnxAcCoZ6pwXufb8i6PFBNEZ2K769TzDtjdxC5Lt4nSJV3w5/liM8jwqJEWhVQk
# sUlWkCdbuxjft7oTDYsPQ+p+aN6rxSy1F1UeJhUW9NwGfOQZd7nAEF45pKcj6r1y
# Wgal6So0HEKY+VCZ1OA3o/yB7glUVfF4vausvNSabMTyebgegOaOc4toeZGJ+0kt
# zZObkveTsN3AE7azMlDjJPeSgudgyW8K0U4zVFIy1okZjt+hggIoMIICJAYJKoZI
# hvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMz
# AAAAtax9bYdrJhFHAAAAAAC1MAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzA3MTkwNDU0MzNaMCMGCSqGSIb3
# DQEJBDEWBBSC2Y6AdK3GDH353pWs2MEGB1TrSTANBgkqhkiG9w0BAQUFAASCAQAE
# xBZwygTDyLIA5DEpgZeE4BFazZDE6V1BQ1zrYl84+WaKGz4HaPNhBIxc2XFTgVcr
# OrZShcMV0u7883OZsKX7nJk/fhAKwqEsJF46GyUJTanAKdl2V+4udz4jw89+ZQdZ
# aVW6p0H2bmL7IchMADSfoLkZmcDMvRPx1FOyPC9mdzvPQx676+s/fm++K7bPgb+d
# B5gvA/iSxVXpfuV6hY45GqbnyBtSk6f/WqBRk9B4orQEi5nRZ2K1Hb3DVL6xRPzu
# BL0g5dinp9Wqbc5SIl6pUVIT5It8c/VgiKQxNgWIbOnrxqn8B3MhzKbt0vC48vf2
# GFWqD4c++88TNTMH+Zxq
# SIG # End signature block
