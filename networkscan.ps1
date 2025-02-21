# Continuous Network Scanning Script
$subnet = "10.0.10."
$commonPorts = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 445, 3389, 8080)
$username = "biggestcpbever"
$password = "biggestcpbever"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $securePassword)

function Test-Host {
    param ($ip)
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        return $true
    } else {
        return $false
    }
}

function Check-OpenPorts {
    param ($ip)
    foreach ($port in $commonPorts) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $tcpClient.Connect($ip, $port)
            Write-Output "$ip has port $port open"
        } catch {
            # Port is closed
        } finally {
            $tcpClient.Close()
        }
    }
}

function Check-NetworkShares {
    param ($ip)
    try {
        $shares = Get-WmiObject -Class Win32_Share -ComputerName $ip -Credential $cred -ErrorAction SilentlyContinue
        if ($shares) {
            Write-Output "Shares found on ${ip}:"
            $shares | ForEach-Object { Write-Output $_.Name }
        } else {
            Write-Output "No shares found on ${ip}"
        }
    } catch {
        Write-Output "Unable to access shares on ${ip}"
    }
}

while ($true) {
    Write-Output "Scanning network..."
    for ($i = 1; $i -le 254; $i++) {
        $ip = "$subnet$i"
        if (Test-Host -ip $ip) {
            Write-Output "Host $ip is online"
            Check-OpenPorts -ip $ip
            Check-NetworkShares -ip $ip
        }
    }
    Start-Sleep -Seconds 30  # Adjust delay as needed
}
