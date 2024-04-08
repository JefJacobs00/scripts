$path =  "HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config\"
$value = "EnableCertPaddingCheck"
function Get-SystemBitVersion {
    $is64Bit = [Environment]::Is64BitOperatingSystem

    if ($is64Bit) {
        return "64"
    } 

    return "32"
}

function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name,
        
        [Switch]$PassThru
    ) 

    process {
        if (!(Test-Path $Path)) {
            return $false
        }

        $Key = Get-Item -LiteralPath $Path
        $Value = $Key.GetValue($Name, $null)

        if ($Value -ne $null) {
            if ($PassThru) {
                return Get-ItemProperty $Path $Name
            }

            return $true
        }

        return $false
    }
}

function Add-Regs {
    $registryPath1 = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
    $registryPath2 = "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"

    $name = "EnableCertPaddingCheck"
    $value = "1"
    
    # Set value for the first registry path
    $reg1 = Test-RegistryValue -Path $registryPath1 -Name $name -PassThru:$false
    if(! $reg1){
        New-Item -Path $registryPath1 -Force | Out-Null
        New-ItemProperty -Path $registryPath1 -Name $name -Value $value -PropertyType String -Force | Out-Null
    }
    
    
    # Secondary value for registry path
    $reg2 = Test-RegistryValue -Path $registryPath2 -Name $name -PassThru:$false
    if(! $reg2){
        $version = Get-SystemBitVersion
        if($version -eq "64"){
            New-Item -Path $registryPath2 -Force | Out-Null
            New-ItemProperty -Path $registryPath2 -Name $name -Value $value -PropertyType String -Force | Out-Null
        }
    }
}

$is_present = 
if(!$is_present){
    Add-Regs
}
