# Tenable SecurityCenter PowerShell API Module
#
# Written by
#
# Josh Scott
# Information Security Architect
# City of Portland, Oregon 
# BTS - Information Security
# josh.scott@portlandoregon.gov

[string]$Script:SCHost
[string]$Script:SCUsername
[string]$Script:SCPassword
[string]$Script:TIOHost
[string]$Script:TIOHeaders
[string]$Script:TIOAccessKey
[string]$Script:TIOSecretKey
[string]$Script:NessusHost
[string]$Script:NessusAccessKey
[string]$Script:NessusSecretKey
[object]$Script:SCSession
[hashtable]$Script:SCHeaders = @{'Content-Type' = 'application/json'}



<#
Function Template {
    <#
        .SYNOPSIS 
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        # >
    
    param(
        )

    process {
        Return $null
        }
    }
    #>

Function Convert-EpochTime {
    <#
        .SYNOPSIS
        Converts an Epoch or Unix time to local time.
        .DESCRIPTION
        Converts an epoch or unix timestamp to a local 12Hour standard time stamp.
        .EXAMPLE
        Convert-EpochTime -EpochTime 
        .PARAMETER parameterexample
        Describe a parameter
        #>
    param (
        [Parameter(Mandatory=$true)]
        [object]$EpochTime
        )
    if($EpochTime -ne $null) {
        $Origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $EpochTime = $Origin.AddSeconds($EpochTime).ToLocalTime()
        }
    Return $EpochTime
    }

Function TPSSetConfig {
    <#
        .SYNOPSIS
        Creates or updates a config file to reduce user input
        .DESCRIPTION
        When invoked it will ask a series of questions and save the responses to a config file.
        .EXAMPLE
        Set-SCSApiConfig
        #>
    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("SecurityCenter","TenableIO","Nessus","NessusManager")]
        [string]$Application
        )

    process {
        [PSCustomObject]$ConfigText
        [hashtable]$ConfigData=[ordered]@{}
        [string]$FileName = Read-Host "Enter a filename for the configuration"
        [string]$ConfigFile = "$env:APPDATA\TPS\Conf\$FileName"
        
        if( -not (Test-Path $ConfigFile)) {
            $TestDir = New-Item -ItemType File -Force $ConfigFile
            }

        if($Application -match "SecurityCenter") {
            $ConfigData.Add('Application',$Application)
            $SCHost = Read-Host "Security Center Host Name"
            $ConfigData.Add('SCHost',$SCHost)
            $SCUsername = Read-Host "Username"
            $ConfigData.Add('Username',$SCUsername)
            $SCPassword = Read-Host "Password" -AsSecureString
            $ConfigData.Add('Password',$($SCPassword |ConvertFrom-SecureString))
            $Default = Read-Host "Would you like to make this the default?(y/n)"
            if($Default.ToLower() -eq 'y'){$Value = '1'}
            if($Default.ToLower() -eq 'n'){$Value = '0'}
            $ConfigData.Add('Default',$Value)
            [PSCustomObject]$ConfigText += $ConfigData
            }

        if($Application -match "tenableio") {
            $ConfigData.Add('Application',$Application)
            $Script:TIOHost = Read-Host "tenable.io Host Name (cloud.tenable.com)"
            $ConfigData.Add('TIOHost',$Script:TIOHost)  
            $Script:TIOAccessKey = Read-Host "Enter the tenable.io API Access Key"
            $ConfigData.Add('AccessKey',$Script:TIOAccessKey)
            $Script:TIOSecretKey = Read-Host "Enter the tenable.io API Secret Key"
            $ConfigData.Add('SecretKey',$Script:TIOSecretKey)
            $Default = Read-Host "Would you like to make this the default?(y/n)"
            if($Default.ToLower() -eq 'y'){$Value = '1'}
            if($Default.ToLower() -eq 'n'){$Value = '0'}
            $ConfigData.Add('Default',$Value)
            [PSCustomObject]$ConfigText += $ConfigData
            }

        if($Application -match "Nessus") {
            $ConfigData.Add('Application',$Application)
            $Script:NessusHost = Read-Host "Nessus Host Name (cloud.tenable.com)"
            $ConfigData.Add('TIOHost',$Script:NessusHost)
            $Script:NessusAccessKey = Read-Host "Enter the Nessus API Access Key"
            $ConfigData.Add('AccessKey',$Script:NessusAccessKey)  
            $Script:SecretKey = Read-Host "Enter the Nessus API Secret Key"
            $ConfigData.Add('SecretKey',$Script:NessusSecretKey)
            $Default = Read-Host "Would you like to make this the default?(y/n)"
            if($Default.ToLower() -eq 'y'){$Value = '1'}
            if($Default.ToLower() -eq 'n'){$Value = '0'}
            $ConfigData.Add('Default',$Value)
            [PSCustomObject]$ConfigText += $ConfigData
            }

        if($Application -match "NessusManager") {
            $ConfigData.Add('Application',$Application)
            $Script:NessusManagerHost = Read-Host "Nessus Manager Host Name (cloud.tenable.com)"
            $ConfigData.Add('TIOHost',$Script:NessusManagerHost)  
            $Script:NessusManagerAccessKey = Read-Host "Enter the Nessus Manager API Access Key"
            $ConfigData.Add('AccessKey',$Script:NessusManagerAccessKey)  
            $Script:NessusManagerSecretKey = Read-Host "Enter the Nessus Manager API Secret Key"
            $ConfigData.Add('SecretKey',$Script:NessusManagerSecretKey)
            $Default = Read-Host "Would you like to make this the default?(y/n)"
            if($Default.ToLower() -eq 'y'){$Value = '1'}
            if($Default.ToLower() -eq 'n'){$Value = '0'}
            $ConfigData.Add('Default',$Value)
            [PSCustomObject]$ConfigText += $ConfigData
            }

        Out-File -InputObject $($ConfigText|ConvertTo-Json) -FilePath $ConfigFile
        }
    }

Function TPSGetConfig {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigId
        )

    process {
        $ConfigFile = TPSListConfig |Where-Object {$_.id -eq $ConfigId} |Select-Object -ExpandProperty file
        Return $(Get-Content -Path "$($env:APPDATA)\TPS\Conf\$ConfigFile")|ConvertFrom-Json
        }
    }

Function TPSLoadConfig {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$ConfigId,
        [string]$ConfigName
        )

    process {

        if($ConfigId) {
            $ConfigFile = TPSListConfig |Where-Object {$_.id -eq $ConfigId} |Select-Object -ExpandProperty file
            $Config = $(Get-Content -Path "$($env:APPDATA)\TPS\Conf\$ConfigFile")|ConvertFrom-Json
        }

        if($ConfigName) {
            $Config = $(Get-Content -Path "$($env:APPDATA)\TPS\Conf\$ConfigName")|ConvertFrom-Json
            }

        if($Config.Application -match "TenableIO") {
            $Script:TIOHost = $Config.TIOHost
            $Script:TIOAccessKey = $Config.AccessKey
            $Script:TIOSecretKey = $Config.SecretKey
            $Script:TIOHeaders = @{"X-ApiKeys" = "accessKey=$Script:TIOAccessKey; secretKey=$Script:TIOSecretKey"}
            Write-Host "Tenable.IO Configuration Loaded"
            }

        if($Config.Application -match "SecurityCenter") {
            $Script:SCHost = $Config.SCHost
            $Script:SCUsername = $Config.Username
            $Script:SCPassword = $Config.Password|ConvertTo-SecureString
            Write-Host "Security Center Configuration Loaded"
            }
        }
    }

Function TPSListConfig {
    $ConfigFiles = Get-ChildItem $env:APPDATA\TPS\Conf\ |Select-Object -ExpandProperty Name
    $Counter = 1
    $Selection = @()
    foreach($Config in $ConfigFiles) {
        $FileMenu = @{
            id = $Counter
            file = $Config
            }
        $Selection += New-Object PSObject -Property $FileMenu
        $Counter++
    }

    Return $Selection
    }

Function TPSLoadDefaultConfig {
    <#
        .SYNOPSIS 
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $DefaultConfig = @()
        $FilePath = "$env:APPDATA\TPS\Conf\"
        $FileNames = Get-ChildITem $FilePath |Select-Object -ExpandProperty Name
        foreach($File in $FileNames) {
            $Config = $(Get-Content "$FilePath$($File)")|ConvertFrom-Json
            if($Config.Default -eq '1'){$DefaultConfig += $Config}
            }
        foreach($Config in $DefaultConfig){
            if($Config.Application -match "TenableIO") {
                $Script:TIOHost = $Config.TIOHost
                $Script:TIOAccessKey = $Config.AccessKey
                $Script:TIOSecretKey = $Config.SecretKey
                $Script:TIOHeaders = @{"X-ApiKeys" = "accessKey=$Script:TIOAccessKey; secretKey=$Script:TIOSecretKey"}
                Write-Host "tenable.io configuration loaded."
                }

            if($Config.Application -match "SecurityCenter") {
                $Script:SCHost = $Config.SCHost
                $Script:SCUsername = $Config.Username
                $Script:SCPassword = $Config.Password|ConvertTo-SecureString
                Write-Host "Security Center configuration loaded."
                }
            }
        }
    }

# Security Center API Call Templates
# For Get,Post,Patch,Delete RestAPI call Methods. 

Function TPSGetSCResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Resource,
        [switch]$Response
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:SCHost)/rest/$($Resource)" -Method Get -Headers $Script:SCHeaders -WebSession $Script:SCSession
        if($Response) {$Request = $Request.response}
        Return $Request
        }
    }

Function TPSPatchResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Resource,
        [string]$Body,
        [switch]$Response
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:SCHost)/rest/$($Resource)" -Method Patch -Headers $Script:SCHeaders -WebSession $Script:SCSession -Body $Body
        if($Response) {$Request = $Request.response}
        Return $Request
        }
    }

Function TPSPostResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Resource,
        [string]$Body,
        [switch]$Response
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:SCHost)/rest/$($Resource)" -Method Post -Headers $Script:SCHeaders -WebSession $Script:SCSession -Body $Body
        if($Response) {$Request = $Request.response}
        Return $Request
        }
    }

# Security Center API Calls

Function TPSShowGreeter {
    <#
        .SYNOPSIS
        Displays Greeting to the current user
        .DESCRIPTION
        Displays information to the user about their last succesful login, and any failed attempts.
        .EXAMPLE
        Show-TPSGreeter
        #>

    process {
        $CurrentUser = TPSGetSCResource -Resource 'currentUser' -Response
        $System = TPSGetSCResource -Resource 'system' -Response
        #Clear-Host
        Write-Host "`r`n"
        Write-Host "Tenable Security Center $($System.version)`r`n"
        Write-Host "$($System.banner)`r`n"
        Write-Host "Welcome back $($CurrentUser.firstname) $($CurrentUser.lastname)"
        Write-Host "`tLast Successful Login:" $(Convert-EpochTime -EpochTime $CurrentUser.lastLogin) "`r"
        Write-Host "`tFrom:" $CurrentUser.lastLoginIP "`r"
        Write-Host "`t$($CurrentUser.failedLogins) failed login attempts since last successful login.`r`n" 
        }
    }

Function TPSConnectSC {
    <#
        .SYNOPSIS
        Invokes a new Security Center API Connection

        .DESCRIPTION
        Invokes a new Security Center API Connection. When run it requests a username, password, and the SecurityCenter hostname. If the '-UseConfig' option is selected it will use a saved config file for the host,username, and password.
        
        .EXAMPLE
        TPSConnectSC
        
        .EXAMPLE
        Invoke-TPS -SaveConfig
        
        .Parameter SaveConfig
        Invokes a cmdlet that will query the user about saving commonly requested information (SecurityCenter Host, Username, Password)
        
        #>
    
    param(
        [switch]$UseDefaultConfig
        )

    process {
        $ErrorActionPreference = "Continue"
        
        if($UseDefaultConfig){
            TPSLoadDefaultConfig
            $Credentials = New-Object -TypeName System.Management.Automation.PSCredential($Script:SCUsername,$Script:SCPassword)
            }
        else {
            $Username = Read-Host "Username"
            $Password = Read-Host "Password" -AsSecureString
            $Script:SCHost = Read-Host "Security Center Host"
            $Credentials = New-Object -TypeName System.Management.Automation.PSCredential($Username,$Password)
            }
        $Credentials = @{'username' = $Credentials.UserName; 'password' = $Credentials.GetNetworkCredential().Password} |ConvertTo-Json -Compress

        $Request = Invoke-RestMethod -Uri "https://$($Script:SCHost)/rest/token" -Method Post -Body $Credentials -SessionVariable WebSession
        $Script:SCHeaders.Add('X-SecurityCenter',$Request.response.token)
        $Script:SCSession = $WebSession
        
        TPSShowGreeter

        }
    }

Function TPSGetSCAsset {
    <#
        .SYNOPSIS
        Returns a list of all assets
        .DESCRIPTION
        Returns a PSObject that contains all Usable and Manageable assets. Or if an an asset ID is provided returns details on a specific asset
        .EXAMPLE
        Get-Asset
        .EXAMPLE
        Get-Asset -Id '15'
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Id,
        [switch]$Usable
        )
    
    process {
        if($Id){
            $Fields = 'id,name,description,status,creator,owner,ownerGroup,targetGroup,groups,type,tags,context,template,createdTime,modifiedTime,repositories,ipCount,assetDataFields,typeFields,viewableIPs'
            $Resource = "asset/$($Id)?fields=$($Fields)"
            }
        else {
            $Fields = 'id,name,description,status,type,tags,repositories,ipCount'
            $Resource = "asset?fields=$($Fields)"
            }
        Return TPSGetSCResource -Resource $Resource -Response
        }
    }

Function TPSUpdateSCAsset {
    <#
        .SYNOPSIS
        Returns a list of all assets
        .DESCRIPTION
        Returns a PSObject that contains all Usable and Manageable assets. Or if an an asset ID is provided returns details on a specific asset
        .EXAMPLE
        Get-Asset
        .EXAMPLE
        Get-Asset -Id '15'
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Id,
        [string]$AssetList,
        [string]$Description,
        [string]$Tags,
        [ValidateSet("static","dynamic","dnsname","ldapquery","combination")][string]$Type
        )
    
    process {
        $Resource = "asset/$Id"
        $Body = @{
            definedDNSNames = $AssetList
            type = $Type
            description = $Description
            tags = $Tags
            } |ConvertTo-Json -Compress -Depth 5

        Return TPSPatchResource -Resource $Resource -Body $Body
        }
    }

Function TPSAddSCAsset {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER $Name
        The name of the new Asset
        .PARAMETER $AssetList
        A comma separated string of values
        .PARAMETER $Tags
        Terms that can make searching for Assets Easier
        #>
    
    param(
        [string]$Name,
        [string]$AssetList,
        [string]$Tags,
        [string]$Description,
        [ValidateSet("static","dynamic","dnsname","ldapquery","combination")][string]$Type
        )
    
    process {
        $Resource = 'asset'
        $Body = @{
            type = $Type
            prepare = "true"
            name = "$Name"
            description = "$Description"
            context = ""
            tags = "$Tags"
            definedDNSNames = "$AssetList"
            } |ConvertTo-Json -Compress -Depth 5

        Return TPSPostResource -Resource $Resource -Body $Body
        }
    }

Function TPSGetSCScan {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )
    
    process {
        $Request = TPSGetSCResource -Resource 'scan' -Response
        Return $Request
        }
    }

Function TPSAddSCScan {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$PolicyID,
        [string]$ScanName,
        [string]$CredentialsID,
        [string]$TargetList
        )

    process {
        
        $ScanName = $ScanName
        $Policy = @{id = $PolicyID}
        $Schedule = @{start = "TZID-America/Los_Angeles:$(Get-Date -Format yyyyMMddTHHmmss00)";repeatRule='FREQ=NOW;INTERVAL=1';type='now'}
        $Zone = @{id = 20}
        $Credentials = @{id = 1}
        $Repository = @{id = 27}
        $Creds = @($Credentials)

        $Body = @{
            name = $ScanName
            description = 'API Launch Single Scan'
            type = 'policy'
            policy = $Policy
            repository = $Repository
            schedule = $Schedule
            zone = $Zone
            ipList = $TargetList
            credentials = $Creds
            dhcpTracking = 'true'
            emailOnLaunch = "true"
            emailOnFinish = "true"
            }| ConvertTo-Json -Compress -Depth 10
        $Response = TPSPostResource -Resource 'scan' -Body $Body
        Return $Response
A        }
    }

Function TPSListSCPolicy {
<#
        .SYNOPSIS
        Retrives all scan policies or a single policy when the is specified.
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [string]$Id,
        [switch]$Usable
        )

    process {
        $Resource = "policy?fields=id,name,description"
        if($Id){$Resource = "policy/$($Id)?fields=id,name,description,status,policyTemplateType,policyTemplate,policyProfileName,creator,tags,status,createdTime,modifiedTime,context,generateXCCDFResults,auditFiles,preferences,targetGroup,owner,ownerGroup,groups,families"}
        $Policies = TPSGetSCResource -Resource $Resource -Response
        if($Usable){if(-not $Id){$Policies = $Policies.Usable}}
        $Policies
        }
    }

Function TPSListSCAuditFile {
<#
        .SYNOPSIS
        Description
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $Resource = "auditFile"
        $Request = TPSGetSCResource -Resource $Resource -Response
        Return $Request.usable
        }
    }

Function TPSListSCCredential {
<#
        .SYNOPSIS
        Description
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $Resource = "credential"
        $Request = TPSGetSCResource -Resource $Resource -Response
        Return $Request.usable
        }
    }

 # tenable.io API Call Templates
 # For Get,Post,Patch,Delete RestAPI call Methods. 

Function TPSGetTIOResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [Parameter(Mandatory=$true)][string]$Resource
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:TIOHost)/$($Resource)" -Method Get -Headers $Script:TIOHeaders
        Return $Request
        }
    }

Function TPSPostTIOResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [Parameter(Mandatory=$true)][string]$Resource,
        [Parameter(Mandatory=$true)][string]$Body
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:TIOHost)/$($Resource)" -Method Post -Headers $Script:TIOHeaders -Body $Body
        }
    }

Function TPSPutTIOResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        [Parameter(Mandatory=$true)][string]$Resource
        )

    process {
        $Request = Invoke-RestMethod -Uri "https://$($Script:TIOHost)/$($Resource)" -Method Put -Headers $Script:TIOHeaders
        }
    }

Function TPSPatchTIOResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        Return $null
        }
    }

Function TPSPatchTIOResource {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        Return $null
        }
    }

Function TPSGetTIOScanners {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $Request = TPSGetTIOResource -Resource 'scanners'
        Return $Request.scanners
        }
    }

Function TPSGetTIOAgents {
    <#
        .SYNOPSIS
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $Agents = @()
        $Scanners = TPSGetTIOScanners

        foreach($Scanner in $Scanners) {
            $Request = TPSGetTIOResource -Resource "scanners/$($Scanner.id)/agents"
            $Agents += $Request.agents
            }

        foreach($Agent in $Agents) {
            if($Agent.linked_on){$Agent.linked_on = Convert-EpochTime -EpochTime $($Agent.linked_on)}
            if($Agent.last_connect){$Agent.last_connect = Convert-EpochTime -EpochTime $($Agent.last_connect)}
            if($Agent.last_scanned){$Agent.last_scanned = Convert-EpochTime -EpochTime $($Agent.last_scanned)}
            }
        return $Agents
        }
    }

Function TPSGetTIOAgentGroup {
    <#
        .SYNOPSIS 
        Describe the function here
        .DESCRIPTION
        Describe the function in more detail
        .EXAMPLE
        Give an example of how to use it
        .EXAMPLE
        Give another example of how to use it
        .PARAMETER parameterexample
        Describe a parameter
        #>
    
    param(
        )

    process {
        $Groups = @()
        $Scanners = $(TPSGetTIOScanners).id
        foreach($Scanner in $Scanners){
            $Group = $(TPSGetTIOResource -Resource "scanners/$Scanner/agent-groups").groups
            if($Group -ne $null){$Group |Add-Member -Name scannerId -MemberType NoteProperty -Value $Scanner}
            $Groups += $Group
            }
        Return $Groups
        }
    }

Export-ModuleMember Convert-EpochTime, TPSConnectSC, TPSListConfig, TPSLoadDefaultConfig, TPSGetConfig, TPSSetConfig, TPSLoadConfig, TPSGetSCResource, TPSPostResource, TPSPatchResource, TPSGetSCAsset, TPSUpdateSCAsset, TPSAddSCAsset, TPSGetSCScan, TPSAddSCScan, TPSListSCPolicy, TPSListSCAuditFile, TPSListSCCredential, TPSGetTIOResource, TPSGetTIOScanners, TPSGetTIOAgents,TPSGetTIOAgentGroup,TPSPutTIOResource