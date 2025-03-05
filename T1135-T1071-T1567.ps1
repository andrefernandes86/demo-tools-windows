$Subnet = "192.168.200."
$EicarURL = "http://malware.wicar.org/data/eicar.com"
$LocalPath = "C:\Users\Public\eicar.com"
$UploadPath = "C$\Windows\Temp\eicar.com"
$User = "skynet"
$Password = "M@ster123"

# Convert credentials for authentication
$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $SecPassword)

# Download the EICAR test file if it doesn't exist
if (!(Test-Path $LocalPath)) {
    Write-Output "Downloading EICAR test file..."
    Invoke-WebRequest -Uri $EicarURL -OutFile $LocalPath
} else {
    Write-Output "EICAR test file already exists."
}

# Scan the subnet for live SMB servers
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    
    # Check if the host is reachable within 2 seconds
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds 2) {
        Write-Output "Host Alive: $IP"

        # Check if SMB (445) is open
        if (Test-NetConnection -ComputerName $IP -Port 445 -InformationLevel Quiet) {
            Write-Output "SMB Open: $IP"

            # Try connecting to the admin share (C$)
            $AdminSharePath = "\\$IP\$UploadPath"

            try {
                Write-Output "Attempting to upload EICAR to \\$IP\C$\Windows\Temp\eicar.com"
                Copy-Item -Path $LocalPath -Destination $AdminSharePath -Credential $Cred -Force
                Write-Output "[SUCCESS] EICAR uploaded to \\$IP\C$\Windows\Temp\eicar.com"
            } catch {
                Write-Output "[ERROR] Failed to upload EICAR to \\$IP\C$\Windows\Temp\ (Access Denied or Share Unavailable)"
            }
        } else {
            Write-Output "[INFO] SMB Not Open on: $IP"
        }
    } else {
        Write-Output "[INFO] Host Unreachable: $IP (Skipping)"
    }
}
