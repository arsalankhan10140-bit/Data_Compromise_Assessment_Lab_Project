# CA-Lab Phase 5: Velociraptor offline collection INSIDE CA-WIN-01 (no server).
# Collects forensic artifacts + raw EVTX (for Hayabusa) into one zip on C:\, then reports the path.
# Run over SSH as admin. velociraptor.exe comes from the read-only share.
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { 'Not the lab VM'; exit 1 }
$velo = '\\VBOXSVR\CA-Lab\tools\velociraptor\velociraptor.exe'
$outdir = 'C:\CA-Collection'; New-Item -ItemType Directory -Force $outdir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$zip = "$outdir\CA-WIN-01-$stamp.zip"

$artifacts = @(
  'Windows.EventLogs.Evtx',          # parsed event logs
  'Windows.Forensics.Prefetch',      # program execution
  'Windows.Forensics.Amcache',       # executed binaries + hashes
  'Windows.System.TaskScheduler',    # scheduled tasks
  'Windows.EventLogs.ScheduledTasks',
  'Windows.Sys.StartupItems',        # autoruns / Run keys / startup
  'Windows.Network.Netstat',         # connections
  'Windows.System.Pslist'            # running processes
)

Write-Host "Collecting (parsed forensic artifacts) -> $zip"
& $velo artifacts collect @artifacts --output $zip *>&1 | Select-Object -Last 3
Write-Host ("parsed zip: {0:N1} MB" -f ((Get-Item $zip).Length/1MB))

# Raw EVTX files for Hayabusa (copied straight from the log store)
$raw = "$outdir\evtx-$stamp"; New-Item -ItemType Directory -Force $raw | Out-Null
Copy-Item 'C:\Windows\System32\winevt\Logs\*.evtx' $raw -ErrorAction SilentlyContinue
$n = @(Get-ChildItem $raw -Filter *.evtx).Count
Write-Host "raw EVTX files copied: $n -> $raw"
Write-Host "DONE zip=$zip evtx=$raw"
