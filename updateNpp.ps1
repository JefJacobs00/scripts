$applicationInstalled = $false
$applicationRegistry = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "Notepad++*" }
$w32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like 'NotePad++*'

if ($applicationRegistry -ne $null) {
    $applicationInstalled = $true
    Write-Host "Notepad++ is installed.";
} elseif ($w32 -ne $null) {
    $applicationInstalled = $true
    Write-Host "Notepad++ is installed.";
    $applicationRegistry = $w32
} else {
    Write-Host "Notepad++ is not installed.";
}



if ($applicationInstalled) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $64bit = $applicationRegistry.DisplayName.Contains("x64");
    $np = Get-Process Notepad++;
    if($np){
        $np | kill;
    }

    if($applicationRegistry.MajorVersion -ne '8'){
        Write-Host "Uninstalling previous version ($applicationRegistry.MajorVersion) before updating"
        Start-Process -FilePath $applicationRegistry.UninstallString -Args "/S" -Verb RunAs -Wait
    }
    # v8.6.2/npp.8.6.2.Installer.x64.exe
    $dlurl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.2/npp.8.6.2.Installer" + (&{If($64bit){".x64.exe"} Else {".exe"}})
    Write-Host "Downloading program from $dlurl"
    $installerPath = Join-Path "c:/temp/" (Split-Path $dlurl -Leaf)
    Invoke-WebRequest $dlurl -OutFile $installerPath
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
    Remove-Item $installerPath
} else {
    Write-Host "Update process skipped because Notepad++ is not installed."
}
