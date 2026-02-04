$logPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
$outCsv  = "C:\Users\Administrator\Desktop\detection\detect_operator\logs\firewall.csv"

Get-Content $logPath |
Where-Object {
    $_ -notmatch "^#" -and $_ -ne ""
} |
ForEach-Object {
    $f = $_ -split "\s+"

    $protocol = $f[3]
    $destPort = $f[7]

    if (
        ($protocol -eq "TCP" -and $destPort -eq "443") -or
        ($destPort -eq "53")
    ) {
        [PSCustomObject]@{
            timestamp = "$($f[0])T$($f[1])"
            src_ip    = $f[4]
            dest_ip   = $f[5]
            port      = $destPort
            protocol  = $protocol
            action    = $f[2]
            type      = "firewall"
        }
    }
} | Export-Csv $outCsv -NoTypeInformation -Encoding UTF8
# powershell.exe -ExecutionPolicy Bypass -File firewall_csv.ps1をdetect_operatorで打つこと
#$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File 'C:\Users\Administrator\Desktop\detection\detect_operator\firewall_csv.ps1'"
#$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue)
#Register-ScheduledTask -TaskName "FirewallCSVExport" -Action $action -Trigger $trigger -RunLevel Highest -User "Administrator"も打つこと