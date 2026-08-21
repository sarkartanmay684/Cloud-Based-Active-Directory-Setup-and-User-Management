$p = "C:\Users\tanmay_admin\Desktop\Domain-Controller-01.evtx"
$output = "$env:USERPROFILE\Desktop\DC01-SecurityEvents.csv"

$ids = 4624,4625,4648,4720,4722,4723,4724,4725,4726,4732,4733,4735,4672,4627,4688,4702

$count = 0

Write-Host "Exporting all matching events..." -ForegroundColor Yellow

Get-WinEvent -FilterHashtable @{
    Path = $p
    Id   = $ids
} -ErrorAction Stop |
ForEach-Object {
    $count++

    if ($count % 1000 -eq 0) {
        Write-Progress `
            -Activity "Exporting security events" `
            -Status "$count events processed"
    }

    $_
} |
Select-Object TimeCreated, Id, RecordId, ProviderName, TaskDisplayName |
Export-Csv -Path $output -NoTypeInformation -Encoding UTF8

Write-Progress -Activity "Exporting security events" -Completed

Write-Host "Completed. Exported $count events." -ForegroundColor Green
Write-Host "File: $output" -ForegroundColor Green
