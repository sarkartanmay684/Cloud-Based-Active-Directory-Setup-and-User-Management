$ids = 4624,4625,4648,4720,4722,4723,4724,4725,4726,4732,4733,4735,4672,4627,4688,4702
Get-WinEvent -Path $p |
  Where-Object { $ids -contains $_.Id } |
  Select-Object TimeCreated, Id, TaskDisplayName,
                @{n='Summary';e={ ($_.Message -split "`r`n")[0] }} |
  Sort-Object TimeCreated |
  Export-Csv "$env:USERPROFILE\Desktop\DC01-SecurityEvents.csv" -NoTypeInformation