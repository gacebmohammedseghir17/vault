$MusicFolder = Join-Path $env:USERPROFILE "Music"
$TestZone = Join-Path $MusicFolder "Ransomware_Test_Zone"

if (!(Test-Path $TestZone)) {
    New-Item -ItemType Directory -Force -Path $TestZone | Out-Null
    Write-Host "[+] Created Ransomware_Test_Zone at $TestZone"
} else {
    Write-Host "[*] Ransomware_Test_Zone already exists at $TestZone"
}

Write-Host "[*] Generating 50 dummy text files..."
$Random = New-Object System.Random
for ($i = 1; $i -le 50; $i++) {
    $FileName = "dummy_$($i.ToString('00')).txt"
    $FilePath = Join-Path $TestZone $FileName
    
    # Generate ~4KB of random data
    $Bytes = New-Object Byte[] 4096
    $Random.NextBytes($Bytes)
    $Content = [System.Convert]::ToBase64String($Bytes)
    
    Set-Content -Path $FilePath -Value $Content
}

Write-Host "[+] Setup complete. 50 files ready for stress testing."
