# PowerShell Dialect Processor for Echo Forge-AI Integrity
# Handles Windows-specific security validation and enterprise integration
# Lineage: RepoReportEcho_092425

param(
    [string]$BasePath = ".",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$LineageId = "RepoReportEcho_092425"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Logging functions
function Write-LogMessage {
    param(
        [string]$Level,
        [string]$Message
    )
    $logEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $logEntry
    if ($Verbose) {
        Write-Verbose $logEntry
    }
}

function Write-InfoLog { param([string]$Message) Write-LogMessage -Level "INFO" -Message $Message }
function Write-WarnLog { param([string]$Message) Write-LogMessage -Level "WARN" -Message $Message }
function Write-ErrorLog { param([string]$Message) Write-LogMessage -Level "ERROR" -Message $Message }

# Generate file checksum
function Get-FileChecksum {
    param(
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
        return $hash.Hash.ToLower()
    }
    catch {
        Write-ErrorLog "Failed to generate checksum for $FilePath`: $_"
        throw
    }
}

# System security assessment
function Get-SystemSecurityAssessment {
    param(
        [string]$OutputPath
    )
    
    Write-InfoLog "Performing Windows system security assessment"
    
    $assessment = @{
        GeneratedBy = "PowerShell Dialect Processor"
        Timestamp = $Timestamp
        LineageId = $LineageId
        System = @{
            ComputerName = $env:COMPUTERNAME
            OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Architecture = $env:PROCESSOR_ARCHITECTURE
        }
        Security = @{}
        Services = @{}
        Network = @{}
        FileSystem = @{}
    }
    
    try {
        # Windows Defender status
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $defenderStatus = Get-MpPreference
            $assessment.Security.WindowsDefender = @{
                RealTimeProtectionEnabled = $defenderStatus.DisableRealtimeMonitoring -eq $false
                CloudProtectionEnabled = $defenderStatus.MAPSReporting -ne 0
                LastFullScan = (Get-MpPreference).ScanScheduleQuickScanTime
            }
        } else {
            $assessment.Security.WindowsDefender = @{ Status = "Not available or not Windows Defender" }
        }
        
        # Firewall status
        try {
            $firewallProfiles = Get-NetFirewallProfile
            $assessment.Security.Firewall = @{}
            foreach ($profile in $firewallProfiles) {
                $assessment.Security.Firewall[$profile.Name] = @{
                    Enabled = $profile.Enabled
                    DefaultInboundAction = $profile.DefaultInboundAction
                    DefaultOutboundAction = $profile.DefaultOutboundAction
                }
            }
        } catch {
            $assessment.Security.Firewall = @{ Status = "Unable to retrieve firewall status" }
        }
        
        # Critical services status
        $criticalServices = @("wuauserv", "wscsvc", "windefend", "eventlog")
        $assessment.Services.Critical = @{}
        foreach ($serviceName in $criticalServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $assessment.Services.Critical[$serviceName] = @{
                        Status = $service.Status.ToString()
                        StartType = $service.StartType.ToString()
                    }
                } else {
                    $assessment.Services.Critical[$serviceName] = @{ Status = "Not found" }
                }
            } catch {
                $assessment.Services.Critical[$serviceName] = @{ Status = "Error retrieving status" }
            }
        }
        
        # Network configuration
        try {
            $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            $assessment.Network.ActiveAdapters = $networkAdapters.Count
            $assessment.Network.Adapters = @()
            foreach ($adapter in $networkAdapters) {
                $assessment.Network.Adapters += @{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    LinkSpeed = $adapter.LinkSpeed
                }
            }
        } catch {
            $assessment.Network = @{ Status = "Unable to retrieve network information" }
        }
        
        # File system security (sample check)
        try {
            $systemDrive = $env:SystemDrive
            $freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'").FreeSpace
            $totalSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$systemDrive'").Size
            $assessment.FileSystem.SystemDrive = @{
                Drive = $systemDrive
                FreeSpaceGB = [math]::Round($freeSpace / 1GB, 2)
                TotalSpaceGB = [math]::Round($totalSpace / 1GB, 2)
                UsagePercentage = [math]::Round((($totalSpace - $freeSpace) / $totalSpace) * 100, 2)
            }
        } catch {
            $assessment.FileSystem = @{ Status = "Unable to retrieve file system information" }
        }
        
    } catch {
        Write-ErrorLog "Error during security assessment: $_"
        $assessment.Error = $_.ToString()
    }
    
    # Convert to JSON and save
    $jsonOutput = $assessment | ConvertTo-Json -Depth 10
    $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Generate checksum
    $checksum = Get-FileChecksum -FilePath $OutputPath
    $checksumPath = "$OutputPath.sha256"
    "$checksum $([System.IO.Path]::GetFileName($OutputPath))" | Out-File -FilePath $checksumPath -Encoding UTF8
    
    Write-InfoLog "Security assessment saved to: $OutputPath"
    Write-InfoLog "Assessment checksum: $checksum"
    
    return $OutputPath
}

# CVE manifest verification
function Test-CveManifests {
    param(
        [string]$CveDirectory,
        [string]$OutputPath
    )
    
    Write-InfoLog "Verifying CVE manifests in: $CveDirectory"
    
    if (-not (Test-Path $CveDirectory)) {
        Write-WarnLog "CVE directory not found: $CveDirectory"
        return $null
    }
    
    $jsonFiles = Get-ChildItem -Path $CveDirectory -Filter "*.json" -File
    
    if ($jsonFiles.Count -eq 0) {
        Write-WarnLog "No JSON files found in: $CveDirectory"
        return $null
    }
    
    $results = @{
        GeneratedBy = "PowerShell Dialect Processor"
        Timestamp = $Timestamp
        LineageId = $LineageId
        SourceDirectory = $CveDirectory
        TotalFiles = $jsonFiles.Count
        Results = @()
        Summary = @{}
    }
    
    $validCount = 0
    $invalidCount = 0
    
    foreach ($file in $jsonFiles) {
        Write-InfoLog "Verifying: $($file.Name)"
        
        $fileResult = @{
            FileName = $file.Name
            FilePath = $file.FullName
            SizeBytes = $file.Length
            LastModified = $file.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            Checksum = ""
            Valid = $false
            Errors = @()
            CveId = ""
            Severity = ""
        }
        
        try {
            # Generate checksum
            $fileResult.Checksum = Get-FileChecksum -FilePath $file.FullName
            
            # Parse JSON
            $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            
            # Validate required fields
            $requiredFields = @("cve_id", "description", "severity", "published_date")
            $missingFields = @()
            
            foreach ($field in $requiredFields) {
                if (-not $jsonContent.PSObject.Properties[$field]) {
                    $missingFields += $field
                }
            }
            
            if ($missingFields.Count -eq 0) {
                $fileResult.Valid = $true
                $fileResult.CveId = $jsonContent.cve_id
                $fileResult.Severity = $jsonContent.severity
                $validCount++
            } else {
                $fileResult.Errors = $missingFields
                $invalidCount++
            }
            
        } catch {
            $fileResult.Errors = @("JSON parsing error: $($_.Exception.Message)")
            $invalidCount++
        }
        
        $results.Results += $fileResult
    }
    
    # Generate summary
    $results.Summary = @{
        ValidCount = $validCount
        InvalidCount = $invalidCount
        SuccessRate = if ($jsonFiles.Count -gt 0) { [math]::Round(($validCount / $jsonFiles.Count) * 100, 2) } else { 0 }
    }
    
    # Save results
    $jsonOutput = $results | ConvertTo-Json -Depth 10
    $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Generate checksum
    $checksum = Get-FileChecksum -FilePath $OutputPath
    $checksumPath = "$OutputPath.sha256"
    "$checksum $([System.IO.Path]::GetFileName($OutputPath))" | Out-File -FilePath $checksumPath -Encoding UTF8
    
    Write-InfoLog "CVE verification results saved to: $OutputPath"
    Write-InfoLog "Results checksum: $checksum"
    
    return $OutputPath
}

# Generate Windows event log analysis
function Get-WindowsEventAnalysis {
    param(
        [string]$OutputPath,
        [int]$HoursBack = 24
    )
    
    Write-InfoLog "Analyzing Windows event logs for the last $HoursBack hours"
    
    $startTime = (Get-Date).AddHours(-$HoursBack)
    $analysis = @{
        GeneratedBy = "PowerShell Dialect Processor"
        Timestamp = $Timestamp
        LineageId = $LineageId
        AnalysisPeriod = @{
            StartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            EndTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            HoursAnalyzed = $HoursBack
        }
        EventSummary = @{}
        SecurityEvents = @{}
        SystemEvents = @{}
    }
    
    try {
        # Security events analysis
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -MaxEvents 1000 -ErrorAction SilentlyContinue
            if ($securityEvents) {
                $analysis.SecurityEvents = @{
                    TotalCount = $securityEvents.Count
                    LogonEvents = ($securityEvents | Where-Object { $_.Id -eq 4624 }).Count
                    LogoffEvents = ($securityEvents | Where-Object { $_.Id -eq 4634 }).Count
                    FailedLogonEvents = ($securityEvents | Where-Object { $_.Id -eq 4625 }).Count
                    AccountLockoutEvents = ($securityEvents | Where-Object { $_.Id -eq 4740 }).Count
                }
            } else {
                $analysis.SecurityEvents = @{ Status = "No security events found or access denied" }
            }
        } catch {
            $analysis.SecurityEvents = @{ Status = "Unable to access security log: $($_.Exception.Message)" }
        }
        
        # System events analysis
        try {
            $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -MaxEvents 1000 -ErrorAction SilentlyContinue
            if ($systemEvents) {
                $analysis.SystemEvents = @{
                    TotalCount = $systemEvents.Count
                    ErrorEvents = ($systemEvents | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
                    WarningEvents = ($systemEvents | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
                    ServiceStartEvents = ($systemEvents | Where-Object { $_.Id -eq 7036 -and $_.Message -like "*started*" }).Count
                    ServiceStopEvents = ($systemEvents | Where-Object { $_.Id -eq 7036 -and $_.Message -like "*stopped*" }).Count
                }
            } else {
                $analysis.SystemEvents = @{ Status = "No system events found" }
            }
        } catch {
            $analysis.SystemEvents = @{ Status = "Unable to access system log: $($_.Exception.Message)" }
        }
        
    } catch {
        Write-ErrorLog "Error during event log analysis: $_"
        $analysis.Error = $_.ToString()
    }
    
    # Save analysis
    $jsonOutput = $analysis | ConvertTo-Json -Depth 10
    $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Generate checksum
    $checksum = Get-FileChecksum -FilePath $OutputPath
    $checksumPath = "$OutputPath.sha256"
    "$checksum $([System.IO.Path]::GetFileName($OutputPath))" | Out-File -FilePath $checksumPath -Encoding UTF8
    
    Write-InfoLog "Event log analysis saved to: $OutputPath"
    Write-InfoLog "Analysis checksum: $checksum"
    
    return $OutputPath
}

# Main execution function
function Invoke-PowerShellDialectProcessor {
    Write-InfoLog "Starting PowerShell Dialect Processor"
    Write-InfoLog "Base directory: $BasePath"
    Write-InfoLog "Lineage ID: $LineageId"
    
    # Create output directories
    $reportsPath = Join-Path $BasePath "reports\powershell"
    if (-not (Test-Path $reportsPath)) {
        New-Item -Path $reportsPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    
    try {
        # System security assessment
        $securityReportPath = Join-Path $reportsPath "system_security_$timestamp.json"
        $securityReport = Get-SystemSecurityAssessment -OutputPath $securityReportPath
        
        # CVE manifest verification
        $cveDirectory = Join-Path $BasePath "data\cve"
        $cveReportPath = Join-Path $reportsPath "cve_verification_$timestamp.json"
        $cveReport = Test-CveManifests -CveDirectory $cveDirectory -OutputPath $cveReportPath
        
        # Windows event log analysis
        $eventReportPath = Join-Path $reportsPath "event_analysis_$timestamp.json"
        $eventReport = Get-WindowsEventAnalysis -OutputPath $eventReportPath
        
        # Generate summary report
        $summaryPath = Join-Path $reportsPath "powershell_processor_summary_$timestamp.txt"
        $summary = @"
# PowerShell Dialect Processor Summary - $LineageId
Generated: $Timestamp

## Generated Reports:
- System Security Assessment: $securityReport
- CVE Verification Report: $cveReport
- Windows Event Analysis: $eventReport

## Report Checksums:
- Security Report: $(if ($securityReport) { Get-FileChecksum -FilePath $securityReport } else { "N/A" })
- CVE Report: $(if ($cveReport) { Get-FileChecksum -FilePath $cveReport } else { "N/A" })
- Event Report: $(if ($eventReport) { Get-FileChecksum -FilePath $eventReport } else { "N/A" })

Processing completed successfully by PowerShell Dialect Processor
Lineage: $LineageId
"@
        
        $summary | Out-File -FilePath $summaryPath -Encoding UTF8
        
        Write-InfoLog "PowerShell dialect processing completed"
        Write-InfoLog "Summary report: $summaryPath"
        
        # Output results
        Write-Host "PowerShell Dialect Processor completed successfully"
        Write-Host "Security Report: $securityReport"
        Write-Host "CVE Report: $cveReport"
        Write-Host "Event Report: $eventReport"
        Write-Host "Summary: $summaryPath"
        
        return @{
            SecurityReport = $securityReport
            CveReport = $cveReport 
            EventReport = $eventReport
            Summary = $summaryPath
        }
        
    } catch {
        Write-ErrorLog "PowerShell dialect processing failed: $_"
        throw
    }
}

# Execute main function if running as script
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-PowerShellDialectProcessor
}