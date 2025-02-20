# Define the URL to fetch the malicious URLs
$vxvaultURL = "https://vxvault.net/URL_List.php"

# Define the download folder on C:\Temp
$downloadPath = "C:\VXVaultDownloads"

# Ensure the download folder exists
if (!(Test-Path -Path $downloadPath)) {
    New-Item -ItemType Directory -Path $downloadPath | Out-Null
}

# Download the list of malicious URLs
try {
    $response = Invoke-WebRequest -Uri $vxvaultURL -UseBasicParsing
} catch {
    Write-Host "Failed to fetch the URL list. Error: $_"
    exit 1
}

# Extract URLs from the response
$matches = $response.Content -split "`n" | Select-String -Pattern "http[s]?://\S+"

if ($matches.Count -eq 0) {
    Write-Host "No URLs found in the list."
    exit 1
}

# Download each file from the list
foreach ($match in $matches) {
    $fileUrl = $match -replace "<.*?>", "" # Remove any HTML tags
    $fileName = [System.IO.Path]::GetFileName($fileUrl)
    
    if ($fileName -match "^\w+\.\w+$") {
        $outputFile = Join-Path -Path $downloadPath -ChildPath $fileName
    } else {
        $outputFile = Join-Path -Path $downloadPath -ChildPath (New-Guid).ToString() + ".bin"
    }

    try {
        Write-Host "Downloading: $fileUrl"
        Invoke-WebRequest -Uri $fileUrl -OutFile $outputFile -UseBasicParsing
        Write-Host "Saved to: $outputFile"
    } catch {
        Write-Host "Failed to download $fileUrl. Error: $_"
    }
}

Write-Host "Download process completed. Files saved to $downloadPath"
