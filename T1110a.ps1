$Subnet = "192.168.200."
$User = "skynet"
$Password = "M@ster123"
$SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $SecPassword)

1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    
    # Check if host is alive with a timeout
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds 2) {
        Write-Output "Host Alive: $IP"

        # Check SMB (port 445)
        if (Test-NetConnection -ComputerName $IP -Port 445 -InformationLevel Quiet) {
            Write-Output "Attempting SMB Login on $IP"
            try {
                Invoke-Command -ScriptBlock { net use \\$IP\C$ } -Credential $Cred -ErrorAction Stop
                Write-Output "SMB Login Successful: $IP"
            } catch {
                Write-Output "SMB Login Failed: $IP"
            }
        }

        # Check RDP (port 3389)
        if (Test-NetConnection -ComputerName $IP -Port 3389 -InformationLevel Quiet) {
            Write-Output "Attempting RDP Login on $IP"
            Start-Process "mstsc.exe" -ArgumentList "/v:$IP" -Credential $Cred
        }
    } else {
        Write-Output "Host Unreachable: $IP (Skipping)"
    }
}
