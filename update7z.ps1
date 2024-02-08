# Check if 7-Zip is installed by querying the uninstall registry key
$sevenZipInstalled = $false
$sevenZipRegistry = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "7-Zip*" }

if ($sevenZipRegistry -ne $null) {
    $sevenZipInstalled = $true
    Write-Host "7-Zip is installed."
} else {
    Write-Host "7-Zip is not installed."
}

if ($sevenZipInstalled) {
    $dlurl = 'https://7-zip.org/' + (Invoke-WebRequest -UseBasicParsing -Uri 'https://7-zip.org/' | Select-Object -ExpandProperty Links | Where-Object {($_.outerHTML -match 'Download')-and ($_.href -like "a/*") -and ($_.href -like "*-x64.exe")} | Select-Object -First 1 | Select-Object -ExpandProperty href)
    $installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
    Invoke-WebRequest $dlurl -OutFile $installerPath
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
    Remove-Item $installerPath
} else {
    Write-Host "Update process skipped because 7-Zip is not installed."
}
