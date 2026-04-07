$baseDir = "..\test_files"
$files = @(
    "safe_1.txt",
    "safe_2.txt",
    "ransom_1.txt",
    "ransom_2.txt",
    "safe_3.pdf"
)

$results = @()

foreach ($fileName in $files) {
    $relativePath = Join-Path $baseDir $fileName
    # Get absolute path to ensure server can find it regardless of CWD
    $absPath = $null
    try {
        $absPath = (Resolve-Path $relativePath).Path
    } catch {
        Write-Host "Error: Could not find file $relativePath"
        continue
    }

    $cmd = ".\target\debug\ipc_client.exe"
            $procArgs = @("scan", $absPath)
            
            $time = Measure-Command {
                $output = & $cmd $procArgs 2>&1
            }
            
            $outputStr = $output | Out-String
             
             if ($fileName -eq "ransom_1.txt") {
                 $outputStr | Out-File "debug_ransom_1.txt"
             }
 
             # Check for specific YARA matches in the JSON response
             # We look for our custom test rules to ensure accuracy and avoid FPs from generic rules
             $isMalicious = $outputStr.Contains('"rule": "Test_Ransom_Note"') -or $outputStr.Contains('"rule": "Test_Encrypted_Header"')
             
             $results += [PSCustomObject]@{
                File = $fileName
                TimeMs = $time.TotalMilliseconds
                Verdict = if ($isMalicious) { "Malicious" } else { "Safe" }
                Output = $outputStr.Trim()
            }
        }
        
        $results | Format-Table -AutoSize
        
        # Save results to CSV for the thesis
        $results | Select-Object File, TimeMs, Verdict | Export-Csv -Path "..\metrics_results.csv" -NoTypeInformation
        Write-Host "Results saved to ..\metrics_results.csv"
