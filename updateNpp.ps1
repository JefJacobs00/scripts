$applicationInstalled = $false
$applicationRegistry = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "Notepad++*" }
$w32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where-Object DisplayName -like 'NotePad++*'

Write-Host $applicationRegistry.MajorVersion;
Write-Host $applicationRegistry.MinorVersion;

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
    $64bit = $applicationRegistry.DisplayName.Contains("x64");
    $v8 = $applicationRegistry.MajorVersion.Equals('8');
    # v8.6.2/npp.8.6.2.Installer.x64.exe
    $dlurl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v"+ (&{If($v8){"8.6.2/npp.8.6.2.Installer"} Else {"7.9.5/npp.7.9.5.Installer"}}) + (&{If($64bit){".x64.exe"} Else {".exe"}})
    Write-Host "Downloading program from $dlurl"
    $installerPath = Join-Path "c:/temp/" (Split-Path $dlurl -Leaf)
    Invoke-WebRequest $dlurl -OutFile $installerPath
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
    Remove-Item $installerPath
} else {
    Write-Host "Update process skipped because Notepad++ is not installed."
}
