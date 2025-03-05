$Subnet = "192.168.200."
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    $SMBOpen = Test-NetConnection -ComputerName $IP -Port 445 -InformationLevel Quiet
    if ($SMBOpen) {
        Write-Output "SMB Open: $IP"
    }
}
