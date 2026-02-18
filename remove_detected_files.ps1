# Remove Detected Files Script
# Run as Administrator!

Write-Host "================================" -ForegroundColor Yellow
Write-Host "MALWARE REMOVAL SCRIPT" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "WARNING: These detections are likely FALSE POSITIVES!" -ForegroundColor Red
Write-Host "Samsung drivers, PrintFab, and Adobe are legitimate software." -ForegroundColor Red
Write-Host ""

$files = @(
    @{
        Path = "C:\Program Files\Samsung\USB Drivers\28_ssconn2\conn\ss_conn_service2.exe"
        PID = 4664
        Name = "Samsung USB Driver Service 2"
    },
    @{
        Path = "C:\Program Files\Samsung\USB Drivers\27_ssconn\conn\ss_conn_service.exe"
        PID = 4708
        Name = "Samsung USB Driver Service"
    },
    @{
        Path = "C:\Program Files\ZEDOnet\PrintFab\PrintFabMonitor.exe"
        PID = 5964
        Name = "PrintFab Monitor"
    },
    @{
        Path = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\IPCBox\AdobeIPCBroker.exe"
        PID = 13668
        Name = "Adobe IPC Broker"
    }
)

foreach ($file in $files) {
    Write-Host ""
    Write-Host "Processing: $($file.Name)" -ForegroundColor Cyan
    Write-Host "  Path: $($file.Path)"
    
    $choice = Read-Host "  Remove this file? (y/n)"
    
    if ($choice -eq 'y') {
        # Stop the process first
        try {
            $proc = Get-Process -Id $file.PID -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "  Stopping process (PID: $($file.PID))..." -ForegroundColor Yellow
                Stop-Process -Id $file.PID -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        } catch {
            Write-Host "  Process already stopped or inaccessible" -ForegroundColor Gray
        }
        
        # Delete the file
        try {
            if (Test-Path $file.Path) {
                Remove-Item -Path $file.Path -Force -ErrorAction Stop
                Write-Host "  ✅ File deleted successfully!" -ForegroundColor Green
            } else {
                Write-Host "  File not found at path" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ❌ Failed to delete: $_" -ForegroundColor Red
            Write-Host "  Try uninstalling the software through Control Panel instead" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Skipped" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "================================" -ForegroundColor Yellow
Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Instead of deleting these files, consider:" -ForegroundColor Cyan
Write-Host "1. Uninstall Samsung USB Drivers via Control Panel if not needed"
Write-Host "2. Uninstall PrintFab via Control Panel if not needed"
Write-Host "3. Adobe IPC Broker is part of Adobe Creative Cloud - probably safe"
Write-Host ""
Write-Host "To uninstall properly:"
Write-Host "  Settings > Apps > Installed Apps > Search and Uninstall"
Write-Host ""
