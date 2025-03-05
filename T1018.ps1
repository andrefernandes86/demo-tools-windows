$Subnet = "192.168.200."
1..254 | ForEach-Object {
    $IP = "$Subnet$_"
    if (Test-Connection -ComputerName $IP -Count 1 -Quiet) {
        Write-Output "Host UP: $IP"
    }
}
