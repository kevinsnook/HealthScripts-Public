<#
.SYNOPSIS
Test-PUREHealth.ps1 - PURE Health Check Script.

.DESCRIPTION 
Performs a series of health checks on PURE hosts and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

.OUTPUT
Results are output to screen, as well as optional log file, HTML report, and HTML email

.EXAMPLE
.\Test-PUREHealth.ps1 -ConfigFile C:\Source\Scripts\PURE\test-purehealth-cfg.ps1
Checks all PURE systems in the organization and outputs the results to the shell window.

.LINK

github\kevinsnook

.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on PURE systems and reports them on a Pass/Fail basis.
If the SendEMail parameter is selected in the config file, an email is sent showing an overall status i.e. whether ANY check has FAILed or everything has PASSed.
Check out the VARIABLES section in the config file to make changes to thresholds/recipients etc
#>

#requires -version 2

[CmdletBinding()]
param (
        [Parameter( Mandatory=$true)]
        [string]$ConfigFile

        
    )



#...................................
# Functions
#...................................
#Just a little function to blink message when running in interactive mode
function Blink-Message {
 param([String]$Message,[int]$Delay,[int]$Count,[ConsoleColor[]]$Colors) 
    $startColor = [Console]::ForegroundColor
    $startLeft  = [Console]::CursorLeft
    $startTop   = [Console]::CursorTop
    $colorCount = $Colors.Length
    for($i = 0; $i -lt $Count; $i++) {
        [Console]::CursorLeft = $startLeft
        [Console]::CursorTop  = $startTop
        [Console]::ForegroundColor = $Colors[$($i % $colorCount)]
        #[Console]::WriteLine($Message)
	write-host $Message -nonewline
        Start-Sleep -Milliseconds $Delay
    }
    [Console]::ForegroundColor = $startColor
}



#This function is used to generate HTML for the server health report
Function New-ServerHealthHTMLTableCell()
{
    param( $lineitem )
    
    $htmltablecell = $null
    
    switch ($($reportline."$lineitem"))
    {
        $success {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Success" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Pass" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Warn" {$htmltablecell = "<td class=""warn""><p class=""blink"">$($reportline."$lineitem")</p></td>"}
        "Access Denied" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Fail" {$htmltablecell = "<td class=""fail""><p class=""blink"">$($reportline."$lineitem")</p></td>"}
        "Could not test service health. " {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        "Unknown" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
        default {$htmltablecell = "<td>$($reportline."$lineitem")</td>"}
    }
    
    return $htmltablecell
}

#This function is used to write the log file if -Log is used
Function Write-Logfile()
{
    param( $logentry )
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logentry" | Out-File $logfile -Append
}

function get_previous_x_day {
param(
$DayofWeek
)

[Int]$DaytoSearchIndex = [DayOfWeek] $DayofWeek  # returns index of day to search for
[Int]$TodayIndex = Get-Date  | Select-Object -ExpandProperty DayOfWeek # returns index of todays day
if ($DaytoSearchIndex -gt $TodayIndex){
    #Today is later in the week than the day required
    #So we need to go back todays index - day's index
    $LastDay = (Get-Date).AddDays(-(7+$TodayIndex-$DaytoSearchIndex)).ToString("dd/MM/yyyy")
    }
else{
    #Today is earlier in the week than the day required
    #So we need to go back day's index - todays index
    $LastDay = (Get-Date).AddDays(-($TodayIndex-$DaytoSearchIndex)).ToString("dd/MM/yyyy")
    }

return $LastDay
}






#...................................
# Script
#...................................

#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path

################################ Initialise some variables #################################################
# dot source the External variables PowerShell File

if (Test-Path $ConfigFile){
    . $ConfigFile
    }
else{
    write-host "Cannot find config file - please create $($ConfigFile)" -ForegroundColor Red
    if ($Log) {Write-Logfile "Cannot find config file - please create $($ConfigFile)"}
    exit
   }

################################ Start a transcript log ####################################################

Start-Transcript -Path $TranscriptFile

#...................................
# Variables
#...................................

$now = Get-Date                                             #Used for timestamps
$date = $now.ToShortDateString()                            #Short date format for email message subject

#Colours for web page
$pass = "Green"
$warn = "Yellow"
$fail = "Red"

#Report variables
$ip = $null
[array]$serversummary = @()                                 #Summary of issues found during server health checks
[array]$report = @()
[array]$failreport = @()
[array]$passreport = @()
[bool]$alerts = $false
$servicestatus = "Pass"
$diskstatus = "Pass"
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ignorelistfile = "$runDir\ignorelist.txt"
$ERRORS=$null
$OVC="Not Connected"
$PUREHosts=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)
write-host $OutputFolder
write-host $ErrorsFile
if (Test-Path $ErrorsFile -PathType Leaf){
    del $ErrorsFile
    }
$SystemErrors = $false                                    #Variable to show whether system errors have been encountered on any node

#Times on PURE are held in GMT (UTC) - so let's work out current offset to GMT
$tz = Get-CimInstance win32_timezone
$GMTOffsetMinutes = ($tz.Bias + $tz.DaylightBias)
$GMTOffsetMinutes


$smtpsettings = @{
From = $fromaddress
SmtpServer = $smtpserver
}

#...................................
# Initialize
#...................................

if (Test-Path "$($OutputFolder)\PURE_Error_Status_Fail.txt"){
    del "$($OutputFolder)\PURE_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " PURE Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


foreach($PUREController in $PUREControllers){ 
    if ($Log) {Write-Logfile "Processing controller $($PUREController)"}
    $PUREArray = $null
    $PUREArray = New-PfaArray -EndPoint $PUREController -Credentials $PURECredential -IgnoreCertificateError -ErrorAction Stop
    Write-Host $PUREController -ForegroundColor Blue
    $PUREArrayAttributes = $null
    $PUREArrayAttributes = Get-PfaArrayAttributes -Array $PUREArray
        
    #Custom object properties
    $serverObj = New-Object PSObject
    if ($PUREArrayAttributes.array_name){
        $serverObj | Add-Member NoteProperty -Name "Array" -Value $PUREArrayAttributes.array_name
        #Null and n/a the rest, will be populated as script progresses
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "System" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Health" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Snapshots" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Alerts" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Networks" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "n/a"
        
        
    
        if ($Log) {Write-Logfile "Processing array $($PUREArrayAttributes.array_name) id $($PUREArrayAttributes.id) running version $($PUREArrayAttributes.version)"}
    

    #...................................
    #DNS Check
    #...................................
            Write-Host "DNS Check: " -NoNewline;
            if ($Log) {Write-Logfile "DNS Check: "}
            $PUREArrayDNS = Get-PfaDnsAttributes -Array $PUREArray
            if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name).$($PUREArrayDNS.domain)"}
            try {$ip = @([System.Net.Dns]::GetHostByName("$($PUREArrayAttributes.array_name).$($PUREArrayDNS.domain)").AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
            catch {
                Write-Host -ForegroundColor $fail $_.Exception.Message
                if ($Log) {Write-Logfile "$_.Exception.Message"}
                $ip = $null
                $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Fail" -Force
                $serversummary += "$($PUREArrayAttributes.array_name) - DNS Lookup Failed"
                }
            if ( $ip -ne $null ){
                Write-Host -ForegroundColor $pass "Pass"
                $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
                if ($Log) {Write-Logfile "DNS Success: $ip"}
                #Is server online
                Write-Host "Ping Check: " -NoNewline;
                if ($Log) {Write-Logfile "Ping check:"}
                $ping = $null
                try {$ping = Test-Connection $PUREController -Quiet -ErrorAction Stop}
                catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                        if ($Log) {Write-Logfile "$_.Exception.Message"}
                        }

                switch ($ping)
                {
                    $true {
                        Write-Host -ForegroundColor $pass "Pass"
                        $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                        if ($Log) {Write-Logfile "Pass"}
                        }
                    default {
                        Write-Host -ForegroundColor $fail "Fail"
                        $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                        $serversummary += "$($PUREController) - Ping Failed"
                        if ($Log) {Write-Logfile "Fail"}
                        }
                    }
                }
            else{
                Write-Host -ForegroundColor $fail "Fail"
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                $serversummary += "$($PUREArrayAttributes.array_name) - $($PUREController) - Ping Failed"
                if ($Log) {Write-Logfile "Fail"}
                }
 
     #...................................
    #System Check
    #...................................
        $SystemOK = $pass
        Write-Host "System Check: " -NoNewline;
        $PUREArrayNTPServers = Get-PfaNtpServers -Array $PUREArray
        if (!$PUREArrayNTPServers.ntpserver){
            write-host "NTP Servers not setup"
            $SystemOK = $warn
            $serversummary += "NTP Servers not setup;"
            if ($Log) {Write-Logfile "NTP Servers not setup"}
                   
            }
        else{
            write-host "NTP Servers setup - $($PUREArrayNTPServers.ntpserver)"
            if ($Log) {Write-Logfile "NTP Servers setup - $($PUREArrayNTPServers.ntpserver)"}
            
            }
 
           
    
        $PUREArrayRemoteAssistSession = Get-PfaRemoteAssistSession -Array $PUREArray
        write-host "Remote assist is $($PUREArrayRemoteAssistSession.status)"
        if ($Log) {Write-Logfile "Remote assist is $($PUREArrayRemoteAssistSession.status)"}
    
        $PUREArrayPhoneHomeStatus = Get-PfaPhoneHomeStatus -Array $PUREArray
        write-host "Phone home is $($PUREArrayPhoneHomeStatus.phonehome)"
        if ($Log) {Write-Logfile "Phone home is $($PUREArrayPhoneHomeStatus.phonehome)"}
    
        $PUREArrayAlerts = Get-PfaAlerts -Array $PUREArray
        if (!$PUREArrayAlerts.enabled){
            $SystemOK = $warn
            $serversummary += "Array alerts are not enabled;"
            if ($Log) {Write-Logfile "Array alerts are not enabled"}
            write-host "Array alerts are not enabled"
            }
    
        $PUREArrayRelayHost = Get-PfaRelayHost -Array $PUREArray
        if (!$PUREArrayRelayHost.relayhost){
            $SystemOK = $warn
            $serversummary += "SMTP relay host not setup;"
            if ($Log) {Write-Logfile "SMTP relay host not setup"}
            write-host "SMTP relay host not setup"
            }
    
        $PUREArraySenderDomain = Get-PfaSenderDomain -Array $PUREArray
        if (!$PUREArraySenderDomain.senderdomain){
            if ($Log) {Write-Logfile "Sender domain not setup"}
            write-host "Sender domain not setup"
            }
    
        $PUREArraySNMPManagers = Get-PfaSnmpManagers -Array $PUREArray
        if (!$PUREArraySNMPManagers.community){
            if ($Log) {Write-Logfile "SNMP not setup"}
            write-host "SNMP not setup"
            }
    
        $PUREArraySyslogServers = Get-PfaSyslogServers -Array $PUREArray
        if (!$PUREArraySyslogServers){
            if ($Log) {Write-Logfile "Syslog not setup"}
            write-host "Syslog not setup"
            }
    
        $PUREArrayDNS = Get-PfaDnsAttributes -Array $PUREArray
        if (!$PUREArrayDNS){
            write-host "$($PUREArrayAttributes.array_name) - DNS Attributes not setup"
            $SystemOK = $fail
            $serversummary += "$($PUREArrayAttributes.array_name) - DNS Attributes not setup;"
            if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - DNS Attributes not setup"}
            }
        if ($PUREArrayDNS.domain){
            if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - DNS domain set to $($PUREArrayDNS.domain)"}
            write-host "DNS domain set to $($PUREArrayDNS.domain)"
            }
        if ($PUREArrayDNS.nameservers){
            foreach ($PUREnameserver in $PUREArrayDNS.nameservers){
                #Is DNS working and correct
                #Ping DNS serevr to add
                if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - Name server set to $($PUREnameserver)"}
                write-host "Name server set to $($PUREnameserver)"
        
                }
            }

        $PUREArrayDirectoryService = Get-PfaDirectoryServiceConfiguration -Array $PUREArray
        if ($PUREArrayDirectoryService){
            if ($Log) {Write-Logfile "$PUREArrayDirectoryService.bind_user`n$PUREArrayDirectoryService.enabled`n$PUREArrayDirectoryService.uri`n$PUREArrayDirectoryService.user_login_attribute`n$PUREArrayDirectoryService.user_object_class`n"}
            if ($Log) {Write-Logfile "$PUREArrayDirectoryService.bind_password`n$PUREArrayDirectoryService.base_dn`n$PUREArrayDirectoryService.check_peer`n"}
            write-host $PUREArrayDirectoryService.bind_user
            write-host $PUREArrayDirectoryService.enabled
            write-host $PUREArrayDirectoryService.uri
            write-host $PUREArrayDirectoryService.user_login_attribute
            write-host $PUREArrayDirectoryService.user_object_class
            write-host $PUREArrayDirectoryService.bind_password
            write-host $PUREArrayDirectoryService.base_dn
            write-host $PUREArrayDirectoryService.check_peer
            }
        else{
            write-host "Directory service not setup"
            $SystemOK = $warn
            $serversummary += "Directory service not setup;"
            if ($Log) {Write-Logfile "Directory service not setup"}
            }

     Switch ($SystemOK) {
            $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "System" -Value "Pass" -Force}
            $warn { Write-Host -ForegroundColor $warn "Warn";$serverObj | Add-Member NoteProperty -Name "System" -Value "Warn" -Force}
            $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "System" -Value "Fail" -Force}
            }
 
    #...................................
    #Volumes check (includes Protection Group and snapshot checks)
    #...................................
            Write-Host "Volumes: " -NoNewline
            if ($Log) {Write-Logfile "Volumes: "}
            $PUREArrayVolumes = Get-PfaVolumes -Array $PUREArray
            $VolumesOK = $pass
            $PGsOK = $pass
            $SnapshotsOK = $pass
            $IntellisnapAddition = "SP-2-"
            foreach ($PUREArrayVolume in $PUREArrayVolumes){
                write-host $PUREArrayVolume.name -ForegroundColor Yellow
                $PUREArrayVolumeIOMetrics = Get-PfaVolumeIOMetrics -Array $PUREArray -VolumeName $PUREArrayVolume.name
                $PUREArrayVolumeSpaceMetrics = Get-PfaVolumeSpaceMetrics -Array $PUREArray -VolumeName $PUREArrayVolume.name
                $PUREArrayVolumeSpace = $PUREArrayVolumeSpaceMetrics.size - $PUREArrayVolumeSpaceMetrics.total
                $PUREArrayVolumeSpacePercentage = [math]::Round(($PUREArrayVolumeSpace / $PUREArrayVolumeSpaceMetrics.size *100),2)
                $PUREArrayVolumeUsedPercentage = 100-$PUREArrayVolumeSpacePercentage
                write-host "Size is $($PUREArrayVolumeSpaceMetrics.size)"
                write-host "Spac is $($PUREArrayVolumeSpace)"
                write-host "Space available on volume $($PUREArrayVolume.name) is $($PUREArrayVolumeSpace) ($($PUREArrayVolumeSpacePercentage)%)"
                switch ($PUREArrayVolumeUsedPercentage){
                    {$_ -gt $VolumeFullPercentageWarning -and $_ -lt $VolumeFullPercentageError} {$VolumesOK = $warn;$serversummary += "Warning - $($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage))% full;";if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full"}}
                    {$_ -gt $VolumeFullPercentageError} {$VolumesOK = $fail;$serversummary += "Error - $($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full;";if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) - $($PUREArrayVolume.name) is $($PUREArrayVolumeUsedPercentage)% full"}}
                    }
            
                $PUREProtectionGroup = Get-PfaProtectionGroups -Array $PUREArray | where {$_.volumes -contains $PUREArrayVolume.name}
                if ($PUREProtectionGroup){
                    write-host "Protection group for $($PUREArrayVolume.name) is $($PUREProtectionGroup.name)"
                    if ($Log) {Write-Logfile "Protection group for $($PUREArrayVolume.name) is $($PUREProtectionGroup.name)"}
                    $PUREPGSchedule = Get-PfaProtectionGroupSchedule -Array $PUREArray -ProtectionGroupName $PUREProtectionGroup.name 
                    if (!$PUREPGSchedule){
                        if ($Log) {Write-Logfile "No Protection Group Schedules for $($PUREProtectionGroup.name)"}
                        $PGsOK = $fail
                        $serversummary += "Error - $($PUREArrayAttributes.array_name) - No Protection Group Schedules for $($PUREProtectionGroup.name);"
                        }
                    }
                if ($Log) {Write-Logfile $PUREArrayVolume.name}
                #Check space and snapshots
                Write-Host "Snapshots Check: " 
                if ($Log) {Write-Logfile "Snapshots Check: "}
                $LastSnapshotOK = $false
                $PURESnapshots = Get-PfaVolumeSnapshots -Array $PUREArray -VolumeName $PUREArrayVolume.name | where {$_.name -notmatch $IntellisnapAddition}
                write-host "snap frequency is $($PUREPGSchedule.snap_frequency/60)"
                Write-Host "Volume Snapshots Count: $($PURESnapshots.Count)"
                if ($Log) {Write-Logfile "Volume Snapshots Count: $($PURESnapshots.Count)"}
                if($PURESnapshots){
                    $LastSnapshot = $PURESnapshots |  sort -Property created | select -Last 1
                    $FirstSnapshot = $PURESnapshots |  sort -Property created | select -First 1
                    $LastSnapShotCreatedDate = get-date $LastSnapshot.Created
                    $LastSnapShotCreatedDate = $LastSnapShotCreatedDate.AddMinutes(-$GMTOffsetMinutes)
                    $LastSnapshotTaken = New-TimeSpan -Start $LastSnapShotCreatedDate -End (Get-Date)
                    $FirstSnapShotCreatedDate = get-date $FirstSnapshot.Created
                    $FirstSnapShotCreatedDate = $FirstSnapShotCreatedDate.AddMinutes(-$GMTOffsetMinutes)
                    $FirstSnapshotTaken = New-TimeSpan -Start $FirstSnapShotCreatedDate -End (Get-Date)
                    write-host "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago at $($LastSnapShotCreatedDate)"
                    if ($Log) {Write-Logfile "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago at $($LastSnapShotCreatedDate)"}
                    if ($LastSnapshotTaken.TotalMinutes -gt $PUREPGSchedule.snap_frequency/60){
                        write-host "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60)"
                        if ($Log) {Write-Logfile "$($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60)"}
                        $SnapshotsOK = $fail
                        $serversummary += "Error - $($LastSnapshot.name) was taken $(([Math]::Round($LastSnapshotTaken.TotalMinutes, 0))) minutes ago which is NOT within the snap frequency of $($PUREPGSchedule.snap_frequency/60);"
                        $LastSnapshotOK = $false
                        }
                    else{
                        $LastSnapshotOK = $true
                        }

                    }
            
                $PUREProtectionGroup = Get-PfaProtectionGroups -Array $PUREArray | where {$_.volumes -contains $PUREArrayVolume.name } #gives a bit more info than the Get-PfaVolumeProtectionGroups version
                if ($PUREProtectionGroup){
                    Write-Host "Protection Group Check: "
                    if ($Log) {Write-Logfile "Protection Group Check: "}
           
                
                    $PUREPGSnapEnabled = $PUREPGSchedule.snap_enabled
                    [int]$PUREPGSnapFrequency = $PUREPGSchedule.snap_frequency
                    Write-Host "PG Snapshot Frequency: $($PUREPGSnapFrequency)"
                    if ($Log) {Write-Logfile  "PG Snapshot Frequency: $($PUREPGSnapFrequency)"}
                
                    switch ($PUREPGSnapFrequency){
                        {$_ -lt 3600} {$PUREPGSnapFrequency_TimeDescriptor = "minutes";$PUREPGSnapFrequency = $PUREPGSnapFrequency/60}
                        {$_ -ge 3600 -and $_ -lt 86400} {$PUREPGSnapFrequency_TimeDescriptor = "hours";$PUREPGSnapFrequency = $PUREPGSnapFrequency/3600}
                        {$_ -ge 86400} {$PUREPGSnapFrequency_TimeDescriptor = "days";;$PUREPGSnapFrequency = $PUREPGSnapFrequency/86400}
                        }
                    $PUREPGReplicationEnabled = $PUREPGSchedule.replicate_enabled
                    [int]$PUREPGReplicationFrequency = $PUREPGSchedule.replicate_frequency
                    if ($Log) {Write-Logfile "PGReplicationFrequency: $($PUREPGReplicationFrequency)"}
                    switch ($PUREPGReplicationFrequency){
                        {$_ -lt 3600} {Write-Logfile "It's under 3600";$PUREPGReplicationFrequency_TimeDescriptor = "minutes";$PUREPGReplicationFrequency = $PUREPGReplicationFrequency/60}
                        {$_ -ge 3600 -and $_ -lt 86400} {$PUREPGReplicationFrequency_TimeDescriptor = "hours";$PUREPGReplicationFrequency = $PUREPGReplicationFrequency/3600}
                        {$_ -ge 86400} {$PUREPGReplicationFrequency_TimeDescriptor = "days";$PUREPGReplicationFrequency = $PUREPGReplicationFrequency/86400}
                        }
                    $PUREPGSnapshots = Get-PfaProtectionGroupSnapshots -Array $PUREArray -Name * | where {$_.source -match $PUREArrayVolume.name} 
                    Write-Host "PG Snapshots Count: $($PUREArrayPGSnapshots.Count)"
                    if ($Log) {Write-Logfile "PG Snapshots Count: $($PUREArrayPGSnapshots.Count)"}
                    $PUREPGSnapshots |  sort -Property created | select -Last 1
                    $PUREPGRetention = Get-PfaProtectionGroupRetention -Array $PUREArray -ProtectionGroupName $PUREProtectionGroup.name
                    $PUREPGRetention | fl
                    [int]$PUREPGall_for = $PUREPGRetention.all_for
                    switch ($PUREPGall_for){
                        {$_ -lt 3600} {$PUREPGall_for_TimeDescriptor = "minutes";$PUREPGall_for = $PUREPGall_for/60}
                        {$_ -ge 3600 -and $_ -lt 86400} {$PUREPGall_for_TimeDescriptor = "hours";$PUREPGall_for = $PUREPGall_for/3600}
                        {$_ -ge 86400} {$PUREPGall_for_TimeDescriptor = "days";$PUREPGall_for = $PUREPGall_for/86400}
                        }
                    $PUREPGperday = $PUREPGRetention.per_day
                    write-host "Retention for $($PUREPGRetention.per_day) per day"
                    $PUREPGdays = $PUREPGRetention.days
                    write-host "Retention for $($PUREPGRetention.days) days"
                    [int]$PUREPGtarget_all_for = $PUREPGRetention.target_all_for
                    write-host $PUREPGRetention.target_all_for
                    switch ($PUREPGtarget_all_for){
                        {$_ -le 3600} {$PUREPGtarget_all_for_TimeDescriptor = "minutes";$PUREPGtarget_all_for = $PUREPGtarget_all_for/60}
                        {$_ -gt 3600 -and $_ -lt 86400} {$PUREPGtarget_all_for_TimeDescriptor = "hours";$PUREPGtarget_all_for = $PUREPGtarget_all_for/3600}
                        {$_ -ge 86400} {$PUREPGtarget_all_for_TimeDescriptor = "days";$PUREPGtarget_all_for = $PUREPGtarget_all_for/86400}
                        }
                    $PUREPGtarget_per_day = $PUREPGRetention.target_per_day
                    $PUREPGtarget_days = $PUREPGRetention.target_days
                
                    #Compare the oldest snapshot to the retained days set in the schedule
                    write-host "$($FirstSnapshot.name) was taken $(([Math]::Round($FirstSnapshotTaken.TotalDays, 0))) days ago at $($FirstSnapShotCreatedDate)"
                    #Have to add a day here as the PURE takes a day to work out the threshold has been traversed and tidy up 
                    write-host "Retention is $($PUREPGRetention.days) days - no snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1))"
                    if (([Math]::Round($FirstSnapshotTaken.TotalDays, 0)) -gt $PUREPGRetention.days+1){
                        write-host "$($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). The oldest was created on $($FirstSnapShotCreatedDate)"
                        $SnapshotsOK = $fail
                        $PGsOK = $fail
                        $serversummary += "Error - $($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). No snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1)). The oldest was created on $($FirstSnapShotCreatedDate);"
                        if ($Log) {Write-Logfile "Error - $($PUREProtectionGroup.name) - There are snapshots older than the maximum retention time ($($PUREPGRetention.days+1)). No snapshots should be retained before $((get-date).AddDays(-$PUREPGRetention.days-1)). The oldest was created on $($FirstSnapShotCreatedDate)"}
                        }

                    write-host "Snapshot Schedule"
                    if ($Log) {Write-Logfile "Snapshot Schedule"}
                    write-host "Enabled: $PUREPGSnapEnabled"
                    if ($Log) {Write-Logfile "Enabled: $PUREPGSnapEnabled"}
                    write-host "Create a snapshot on source every $($PUREPGSnapFrequency) $($PUREPGSnapFrequency_TimeDescriptor)"
                    if ($Log) {Write-Logfile "Create a snapshot on source every $($PUREPGSnapFrequency) $($PUREPGSnapFrequency_TimeDescriptor)"}
                    write-host "Retain all snapshots on source for $($PUREPGall_for) $($PUREPGall_for_TimeDescriptor)"
                    if ($Log) {Write-Logfile "Retain all snapshots on source for $($PUREPGall_for) $($PUREPGall_for_TimeDescriptor)"}
                    write-host "`tthen retain $($PUREPGperday) snapshots per day for $($PUREPGdays) more days"
                    if ($Log) {Write-Logfile "`tthen retain $($PUREPGperday) snapshots per day for $($PUREPGdays) more days"}
                    write-host "Replication Schedule"
                    if ($Log) {Write-Logfile "Replication Schedule"}
                    write-host "Enabled: $PUREPGReplicationEnabled"
                    if ($Log) {Write-Logfile "Enabled: $PUREPGReplicationEnabled"}
                    write-host "Replicate a snapshot to targets every $($PUREPGReplicationFrequency) $($PUREPGReplicationFrequency_TimeDescriptor)"
                    if ($Log) {Write-Logfile  "Replicate a snapshot to targets every $($PUREPGReplicationFrequency) $($PUREPGReplicationFrequency_TimeDescriptor)"}
                    write-host "Retain all snapshots on targets for $($PUREPGtarget_all_for) $($PUREPGtarget_all_for_TimeDescriptor)"
                    if ($Log) {Write-Logfile "Retain all snapshots on targets for $($PUREPGtarget_all_for) $($PUREPGtarget_all_for_TimeDescriptor)"}
                    write-host "`tthen retain $($PUREPGtarget_per_day) snapshots per day for $($PUREPGtarget_days) more days"
                    if ($Log) {Write-Logfile "`tthen retain $($PUREPGtarget_per_day) snapshots per day for $($PUREPGtarget_days) more days"}
                    #How many snapshots taken per day 
                    $PGSnapshotsperday = (86400/$PUREPGSchedule.snap_frequency)
                    Write-Host "PG Policy Snapshots per day Count: $($PGSnapshotsperday)"
                    if ($Log) {Write-Logfile "PG Policy Snapshots per day Count: $($PGSnapshotsperday)"}
                    $TotalDailyPGSnapshotsRetained = ($PGSnapshotsperday*($PUREPGRetention.all_for/86400))
                    Write-Host "PG Policy Total Daily Snapshots Retained Count: $($TotalDailyPGSnapshotsRetained)"
                    if ($Log) {Write-Logfile "PG Policy Total Daily Snapshots Retained Count: $($TotalDailyPGSnapshotsRetained)"}
                    #How many days retention 
                    $TotalPreviousDailyPGSnapshotsRetained = $PUREPGperday*$PUREPGdays
                    Write-Host "PG Total Previous Daily Snapshots Retained Count: $($TotalPreviousDailyPGSnapshotsRetained)"
                    if ($Log) {Write-Logfile "PG Total Previous Daily Snapshots Retained Count: $($TotalPreviousDailyPGSnapshotsRetained)"}
                    $PGRetainedSnapshots = $TotalDailyPGSnapshotsRetained + $TotalPreviousDailyPGSnapshotsRetained
                    Write-Host "Overall PG Total Daily Snapshots Retained Count: $($PGRetainedSnapshots)"
                    switch ($PGRetainedSnapshots - $PUREPGSnapshots.Count){
                        {$_ -lt 0} {write-host "$($PUREProtectionGroup.name) - There are too many snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                                if ($Log) {Write-Logfile "$($PUREProtectionGroup.name) - There are too many snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"}
                                }
                        {$_ -gt 0} {
                            if ($LastSnapshotOK){
                                write-host "$($PUREProtectionGroup.name) - There are too few snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                                write-host "$($PUREProtectionGroup.name) - There are too few snapshots retained but it's OK because the latest snapshot is up-to-date so we are probably catching up"
                                if ($Log) {Write-Logfile "$($PUREProtectionGroup.name) - There are too few snapshots retained but it's OK because the latest snapshot is up-to-date so we are probably catching up"}
                                }
                            else{
                                write-host "$($PUREProtectionGroup.name) - There are too few snapshots retained - Policy set to $($PGRetainedSnapshots) but $($PUREPGSnapshots.Count) actually retained"
                                write-host "$($PUREProtectionGroup.name) - There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago)"
                                if ($Log) {Write-Logfile "$($PUREProtectionGroup.name) - There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago)"}
                                $SnapshotsOK = $fail
                                $PGsOK = $fail
                                $serversummary += "$($PUREProtectionGroup.name) - There are too few snapshots retained and the last snapshot is not within the snapshot frequency configured (taken $($LastSnapshotTaken.Minutes) minutes ago);"
                   
                                }
                            }
                       } 
                    }
                #exit
                }
        

        Switch ($VolumesOK) {
            $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Pass" -Force}
            $warn { Write-Host -ForegroundColor $warn "Warn";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Warn" -Force}
            $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Volumes" -Value "Fail" -Force}
            }

        Switch ($PGsOK) {
            $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value "Pass" -Force}
            $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Protection Groups" -Value "Fail" -Force}
            }

        Switch ($SnapshotsOK) {
            $pass { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Pass" -Force}
            $fail { Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Snapshots" -Value "Fail" -Force}
            }




    #...................................
    #Controller Alarms check
    #...................................
            Write-Host "Controller Alerts: " -NoNewline
            if ($Log) {Write-Logfile "Controller Alerts: "}
        
            $AlertDate = $(get-date).AddHours(-$MaxHoursToScanLog)
            if ($Log) {Write-Logfile "Looking for alerts after $($AlertDate)"}
            write-host "Looking for alerts after $($AlertDate)"
            $AlertResults = Get-PfaRecentMessages -Array $PUREArray | where {$_.current_severity -eq "warning" -or $_.current_severity -eq "error" -or $_.current_severity -eq "critical"} | Select component_name, opened, component_type,event,details,current_severity | where {$_.opened -gt $AlertDate}
            if ($AlertResults){
                $errorhtmlhead="<html>
                        <style>
                        BODY{font-family: Tahoma; font-size: 8pt;}
                        H1{font-size: 16px;}
                        H2{font-size: 14px;}
                        H3{font-size: 12px;}
                        TABLE{Margin: 0px 0px 0px 4px;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                        tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                        th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
                        td{Vertical-Align: Top;Padding: 1px 4px 1px 4px;}
                        td.pass{background: #7FFF00;}
                        td.warn{background: #FFE600;}
                        td.fail{background: #FF0000; color: #ffffff;}
                        td.info{background: #85D4FF;}
                        </style>"
                
                $AlertResults | ConvertTo-HTML -head $errorhtmlhead| out-file $ErrorsFile -append
                }
            Switch (!$AlertResults) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Pass" -Force;if ($Log) {Write-Logfile "No controller alerts"}}
                $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($PUREArrayAttributes.array_name) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
                default { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($PUREArrayAttributes.array_name) - System Errors - Check log for errors (click link above);";$serverObj | Add-Member NoteProperty -Name "Alerts" -Value "Fail" -Force;$SystemErrors = $true;if ($Log) {Write-Logfile "There are controller alerts`n`r$AlertResults"}}
                }
        
    #...................................        
    #Networks check
    #...................................
            Write-Host "Networks: " -NoNewline
            if ($Log) {Write-Logfile "Networks: "}
        
            $NetworkOK = $true

            $PUREInterfaces = Get-PfaNetworkInterfaces  -Array $PUREArray | where {$_.enabled -eq "true"}
            foreach ($PUREArrayNetworkInterface in $PUREInterfaces){
                write-host $PUREArrayNetworkInterface.address 
                if ($PUREArrayNetworkInterface.subnet ){
                    write-host $PUREArrayNetworkInterface.subnet 
                    }   
                write-host $PUREArrayNetworkInterface.mtu      
                write-host $PUREArrayNetworkInterface.hwaddr   
                write-host $PUREArrayNetworkInterface.netmask   
                if ($PUREArrayNetworkInterface.slaves ){
                    write-host $PUREArrayNetworkInterface.slaves
                    }   
          
                write-host $PUREArrayNetworkInterface.services 
                write-host $PUREArrayNetworkInterface.speed    
                write-host $PUREArrayNetworkInterface.gateway   
                if ($Log) {Write-Logfile "Address=$($PUREArrayNetworkInterface).address`nSubnet=$($PUREArrayNetworkInterface).subnet`nMTU=$($PUREArrayNetworkInterface).mtu`nSubnetMask=$($PUREArrayNetworkInterface).netmask`n"}
                if ($Log) {Write-Logfile "Slaves=$($PUREArrayNetworkInterface).slaves`nServices=$($PUREArrayNetworkInterface).services`nSpeed=$($PUREArrayNetworkInterface).speed`nHWAddr=$($PUREArrayNetworkInterface).hwaddr`nGateway=$($PUREArrayNetworkInterface).gateway`n"}
                }
   

            #$PUREInterfaces | fl
            foreach ($PUREInterface in $PUREInterfaces){
                $ip = $PUREInterface.address
                if ( $ip -ne $null ){
                    #Is server online
                    if ($Log) {Write-Logfile "Ping check:"}
                    $ping = $null
                    try {$ping = Test-Connection $ip -Quiet -ErrorAction Stop}
                    catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                        if ($Log) {Write-Logfile "$_.Exception.Message"}
                        }
                    }
                if (!$ping) {
                    $NetworkOK = $false
                    $serversummary += "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable;"
                        
                    if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable"}
                    write-host "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is not pingable"
                    }
                else{
                    if ($Log) {Write-Logfile "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is pingable"}
                    write-host "$($PUREArrayAttributes.array_name) -  interface $($PUREInterface.name) at address $($PUREInterface.address) is pingable"
                    }
                }
            Switch ($NetworkOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Pass" -Force}
                $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
                }

    #...................................        
    #Hosts check
    #...................................
    
    
        $PUREArrayHosts = Get-PfaHosts -Array $PUREArray
        foreach ($PUREArrayHost in $PUREArrayHosts){
            write-host $PUREArrayHost.name
            write-host $PUREArrayHost.wwn
            write-host $PUREArrayHost.hgroup
            #Anything here to check?
            }
        $PUREArrayHostGroups = Get-PfaHostGroups -Array $PUREArray
        foreach ($PUREArrayHostGroup in $PUREArrayHostGroups){
            write-host $PUREArrayHostGroup.name
            write-host $PUREArrayHostGroup.hosts
            }
 
     #...................................        
    #Ports check
    #...................................

        $PUREArrayPorts = Get-PfaArrayPorts -Array $PUREArray
        foreach ($PUREArrayPort in $PUREArrayPorts){
            write-host $PUREArrayPort.name
            write-host $PUREArrayPort.wwn
            write-host $PUREArrayPort.failover
            }
    


    #...................................        
    #Hardware check
    #...................................
            #Controller, Disks,Shelves
            Write-Host "Hardware: " -NoNewline
            if ($Log) {Write-Logfile "Hardware: "}
        
            $HardwareOK = $true

            #All Hardware
            $PUREArrayALLHealthAttributes = Get-PfaAllHardwareAttributes -Array $PUREArray | where {$_.status -notmatch "ok" -and $_.status -notmatch "not_installed"}
            if ($PUREArrayALLHealthAttributes){
                $HardwareOK = $false
                foreach ($PUREArrayALLHealthAttribute in $PUREArrayALLHealthAttributes){
                    if ($Log) {Write-Logfile "Hardware Issue on $($PUREArrayAttributes.array_name) - $($PUREArrayALLHealthAttribute.Name) is $($PUREArrayALLHealthAttribute.status)"}
                    write-host "Hardware Issue on $($PUREArrayAttributes.array_name) - $($PUREArrayALLHealthAttribute.Name) is $($PUREArrayALLHealthAttribute.status)"
                    $serversummary += "Hardware Issue on $($PUREArrayAttributes.array_name) - $($PUREArrayALLHealthAttribute.Name) is $($PUREArrayALLHealthAttribute.status);"
                    }
                }

                
            #Controllers
            $PUREArrayControllers = Get-PfaControllers -Array $PUREArray | where {$_.type -eq "array_controller"}
            foreach ($PUREArrayController in $PUREArrayControllers){
                if ($PUREArrayController.status -ne "ready"){
                    $HardwareOK = $false
                    if ($Log) {Write-Logfile "Controller $($PUREArrayController.name) model $($PUREArrayController.model) is $($PUREArrayController.status)"}
                    write-host "Controller $($PUREArrayController.name) model $($PUREArrayController.model) is $($PUREArrayController.status)"
                    $serversummary += "Controller $($PUREArrayController.name) model $($PUREArrayController.model) is $($PUREArrayController.status);"
                    }
                }
            #exit

            #Disks
            $PUREArrayBadDisks = Get-PfaAllDriveAttributes -Array $PUREArray | where {$_.status -notmatch "healthy" -and $_.status -notmatch "unused"}
            if ($PUREArrayBadDisks){
                $HardwareOK = $false
                if ($Log) {Write-Logfile "Bad disk(s) on $($PUREArray)"}
                write-host "Bad disk(s) on $($PUREArray)"
                $serversummary += "Bad disk(s) on $($PUREArrayAttributes.array_name);"
                
                }
       

            #Shelves
            $PUREShelfControllers = Get-PfaControllers -Array $PUREArray | where {$_.type -eq "shelf_controller"}
            foreach ($PUREShelfController in $PUREShelfControllers){
                if ($PUREShelfController.status){
                    $HardwareOK = $false
                    if ($Log) {Write-Logfile "Controller $($PUREShelfController.name) model $($PUREShelfController.model) is $($PUREShelfController.status)"}
                    write-host "Controller $($PUREShelfController.name) model $($PUREShelfController.model) is $($PUREShelfController.status)"
                    $serversummary += "Controller $($PUREShelfController.name) model $($PUREShelfController.model) is $($PUREShelfController.status);"
            
                    }
            

                }
        
        
            Switch ($HardwareOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
                $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
                }
        

           

    
            #Add this servers output to the $report array
            $report = $report + $serverObj
    
            }         
       

    else{
        $serversummary += "Cannot connect to $($PUREController)"
        if ($Log) {Write-Logfile "Cannot connect to $($PUREController)"}
    
        }
    }

### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\PURE_Error_Status_Fail.txt"
        
        #Generate the HTML
        $coloredheader = "<h1 align=""center""><a href=$ReportURL  class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>PURE Health Details</h3>
                        <p>The following server errors and warnings were detected.</p>
                        <p>
                        <ul>"
        foreach ($reportline in $serversummary)
        {
            $serversummaryhtml +="<li>$reportline</li>"
        }
        $servicestatus = "Fail"
        $serversummaryhtml += "</ul></p>"
        $alerts = $true
    }
    else
    {
        #Generate the HTML to show no alerts
        $coloredheader = "<h1 align=""center""><a href=$ReportURL style=""color:$pass"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>PURE Health Details</h3>
                        <p>No PURE health errors or warnings.</p>"
    }

    
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>PURE GreenScreen - $servicestatus</title>
                <meta http-Equiv=""Cache-Control"" Content=""no-cache"">
                <meta http-Equiv=""Pragma"" Content=""no-cache"">
                <meta http-Equiv=""Expires"" Content=""0"">
                </head>
                <style>
                BODY{font-family: Tahoma; font-size: 8pt;}
                H1{font-size: 16px;}
                H2{font-size: 14px;}
                H3{font-size: 12px;}
                TABLE{Margin: 0px 0px 0px 4px;width: 100%;Border: 1px solid rgb(190, 190, 190);Font-Family: Tahoma;Font-Size: 8pt;Background-Color: rgb(252, 252, 252);}
                tr:hover td{Background-Color: rgb(0, 127, 195);Color: rgb(255, 255, 255);}
                tr:nth-child(even){Background-Color: rgb(110, 122, 130);}th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
                td{Vertical-Align: Top;Padding: 1px 4px 1px 4px;}
                td.pass{background: #7FFF00;}
                td.warn{background: #FFE600;}
                td.fail{background: #FF0000; color: #ffffff;}
                td.info{background: #85D4FF;}
                </style>
                <style>
      		    .blink {
      		    animation: blinker 0.8s linear infinite;
                font-weight: bold;
                }
                @keyframes blinker {  
                50% { opacity: 0; }
                }
                </style>
                <body>
                $coloredheader
                <h3 align=""center"">Generated: $reportime</h3>"
                   
    #PURE Health Report Table Header
    $htmltableheader = "<h3>PURE Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Array</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>System</th>
                        <th>Protection Groups</th>
                        <th>Snapshots</th>
                        <th>Alerts</th>
                        <th>Networks</th>
                        <th>Hardware</th>
                        <th>Volumes</th>
                        </tr>"

    if ($SystemErrors){            
                $htmlhead += "<a href=""$ErrorsURL"">Error Report File</a>"
                }

    #PURE Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader  
    
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        if ($line -match "Fail" -or $line -match "Warn"){
            write-host "$($line.array) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.array) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }                  
                        
    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.array)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Protection Groups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

     #Add passes to bottom of table so they show up last
    foreach ($reportline in $passreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.array)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "DNS")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Protection Groups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Snapshots")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Alerts")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Volumes")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    $serverhealthhtmltable = $serverhealthhtmltable + "</table></p>"

    $htmltail = "</body>
                </html>"

    $htmlreport = $htmlhead + $serverhealthhtmltable + $serversummaryhtml + $htmltail
    
    if ($ReportMode -or $ReportFile)
    {
        $htmlreport | Out-File $ReportFile -Encoding UTF8
    }

    if ($SendEmail)
    {
        if ($alerts -eq $false -and $AlertsOnly -eq $true)
        {
            #Do not send email message
            Write-Host "DO NOT send email message"
            if ($Log) {Write-Logfile "DO NOT send email message"}
        }
        else
        {
            #Send email message
            Write-Host "DO send email message - $servicestatus"
            $servicestatus = $servicestatus.ToUpper()
            if ($servicestatus -eq "FAIL"){
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Priority High
                }
            else
                {
                Send-MailMessage @smtpsettings -To $recipients -Subject "$servicestatus - $reportsubject - $reportime" -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
                }
        }
    }
}
### End report generation


Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

