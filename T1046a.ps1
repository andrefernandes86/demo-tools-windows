$Subnet = "192.168.200."
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    $TCPConnection = Test-NetConnection -ComputerName $IP -Port 3389 -InformationLevel Quiet
    if ($TCPConnection) {
        Write-Output "RDP Open: $IP"
    }
}
