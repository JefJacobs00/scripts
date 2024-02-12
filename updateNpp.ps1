$applicationInstalled = $false
$applicationRegistry = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "Notepad++*" }

if ($applicationRegistry -ne $null) {
    $applicationInstalled = $true
    Write-Host "Notepad++ is installed."
} else {
    Write-Host "Notepad++ is not installed."
}

if ($applicationInstalled) {
    $dlurl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.2/npp.8.6.2.Installer.x64.exe"
    $installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
    Invoke-WebRequest $dlurl -OutFile $installerPath
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
    Remove-Item $installerPath
} else {
    Write-Host "Update process skipped because Notepad++ is not installed."
}
