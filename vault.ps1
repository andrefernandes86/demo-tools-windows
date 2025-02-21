# Ignore SSL/TLS Certificate Errors
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Define the URL of the VX Vault list and the destination directory
$urlList = "https://vxvault.net/URL_List.php"
$destinationDir = "C:\MalwareSamples"  # Ensure this directory exists and is secured

# Create the destination directory if it doesn't exist
if (-not (Test-Path -Path $destinationDir)) {
    New-Item -Path $destinationDir -ItemType Directory | Out-Null
}

# Download the URL list
try {
    $urlContent = Invoke-WebRequest -Uri $urlList -UseBasicParsing
    $urls = $urlContent.Content -split "`n" | Select-String -Pattern "^http" | ForEach-Object { $_.ToString().Trim() }
} catch {
    Write-Error "Failed to retrieve the URL list: $_"
    exit 1
}

# Download each file with a 3-second timeout
foreach ($url in $urls) {
    try {
        $fileName = $url.Split("/")[-1]
        if (-not $fileName) { $fileName = "unknown_file.dat" }  # Handle empty filenames
        $filePath = Join-Path -Path $destinationDir -ChildPath $fileName

        # Create a web request with a 3-second timeout
        $request = [System.Net.WebRequest]::Create($url)
        $request.Timeout = 3000  # 3 seconds timeout

        # Get the response and download the file
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $fileStream = [System.IO.File]::Create($filePath)
        $stream.CopyTo($fileStream)

        # Close the streams
        $fileStream.Close()
        $stream.Close()
        $response.Close()

        Write-Host "Successfully downloaded: ${fileName}"

    } catch {
        Write-Warning "Failed to download ${url}: Skipping..."
        continue
    }
}
