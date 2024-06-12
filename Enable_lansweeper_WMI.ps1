# Run winmgmt -standalonehost
& winmgmt -standalonehost

# Stop the Windows Management Instrumentation (WMI) service
Stop-Service Winmgmt -Force

# Start the Windows Management Instrumentation (WMI) service
Start-Service Winmgmt

# Add a firewall rule for TCP port 24158
New-NetFirewallRule -DisplayName "WMIFixedPort" -Direction Inbound -LocalPort 24158 -Protocol TCP -Action Allow
