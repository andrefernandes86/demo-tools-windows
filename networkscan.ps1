# PowerShell Script for Parallel Network Scanning with Immediate Processing

$ips = @("10.0.10.1", "10.0.10.102", "10.0.10.151", "10.0.10.150", "10.0.10.200", "10.0.10.100")
$commonPorts = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 445, 3389, 8080)
$username = "biggestcpbever"
$password = "biggestcpbever"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $securePassword)

$maxParallelJobs = 10  # Adjust for performance

function Scan-Ports {
    param ($ip)
    foreach ($port in $commonPorts) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $tcpClient.Connect($ip, $port)
            Write-Output "[+] ${ip} has port ${port} open"
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
            Write-Output "[+] Shares found on ${ip}:"
            $shares | ForEach-Object { Write-Output "    - $_.Name" }
        } else {
            Write-Output "[-] No shares found on ${ip}"
        }
    } catch {
        Write-Output "[-] Unable to access shares on ${ip}"
    }
}

# Start scanning the network in parallel
while ($true) {
    Write-Host "Starting parallel network scan..."

    $jobs = @()

    foreach ($ip in $ips) {
        if ($jobs.Count -ge $maxParallelJobs) {
            # Wait for a job to complete before starting a new one
            $done = Wait-Job -Any $jobs
            Remove-Job -Id $done
            $jobs = Get-Job
        }

        $job = Start-Job -ScriptBlock {
            param ($ip, $commonPorts, $cred)

            # Ping the host
            if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
                Write-Output "[+] Host is online: ${ip}"

                # Start immediate port scanning in parallel
                Start-Job -ScriptBlock {
                    param ($ip, $commonPorts)
                    foreach ($port in $commonPorts) {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        try {
                            $tcpClient.Connect($ip, $port)
                            Write-Output "[+] Open Port: ${port} on ${ip}"
                        } catch {
                            # Port is closed
                        } finally {
                            $tcpClient.Close()
                        }
                    }
                } -ArgumentList $ip, $commonPorts | Out-Null

                # Start immediate network share checking in parallel
                Start-Job -ScriptBlock {
                    param ($ip, $cred)
                    try {
                        $shares = Get-WmiObject -Class Win32_Share -ComputerName $ip -Credential $cred -ErrorAction SilentlyContinue
                        if ($shares) {
                            Write-Output "[+] Shares found on ${ip}:"
                            $shares | ForEach-Object { Write-Output "    - $_.Name" }
                        } else {
                            Write-Output "[-] No shares found on ${ip}"
                        }
                    } catch {
                        Write-Output "[-] Unable to access shares on ${ip}"
                    }
                } -ArgumentList $ip, $cred | Out-Null
            }
        } -ArgumentList $ip, $commonPorts, $cred

        $jobs += $job
    }

    # Wait for all jobs to finish before restarting the scan
    Write-Host "Waiting for scans to complete..."
    Get-Job | Wait-Job | Receive-Job
    Get-Job | Remove-Job

    Write-Host "Sleeping for 30 seconds before next scan..."
    Start-Sleep -Seconds 30
}
