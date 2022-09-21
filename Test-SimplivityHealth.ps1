<#
.SYNOPSIS
Test-SimplivityHealth.ps1 - Simplivity Health Check Script.

.DESCRIPTION 
Performs a series of health checks on Simplivity hosts and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.EXAMPLE
.\Test-simplivityHealth.ps1 -ConfigFile C:\Source\Scripts\Simplivity\test-simplivityhealth-cfg.ps1
Checks all Simplivity systems in the organization and outputs the results to the shell window.

.LINK

github\kevinsnook

.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on Simplivity servers in a federation and reports them on a Pass/Fail basis.
If the SendEMail parameter is selected an email is sent showing an overall status i.e. if ANY check has FAILed or everything has PASSed.
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


function Get_Diskspace 	{
param (
    $HostList
)

foreach ($OVCHost in $HostList){
    ################################ DISK CHECKS START ################################
    #A few calculations
    #"Disk checks"
    $OVCPercentFreeSpace = [math]::round($OVCHost.FreeSpaceGB/$OVCHost.AllocatedCapacityGB*100)
    if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  Disk space is $($OVCPercentFreeSpace)%"}
    if ($OVCPercentFreeSpace -lt 10){
        write-host "$($OVCHost.HostName) is low on disk space. ($($OVCHost.FreeSpaceGB)GB free space ($($OVCPercentFreeSpace)% after compression)" -ForegroundColor $fail
        "$($OVCHost.HostName) is low on disk space. ($($OVCHost.FreeSpaceGB)GB free space ($($OVCPercentFreeSpace)% after compression)" 
        }
    try{$Hardware = Get-SVThardware -hostname $OVCHost.HostName}
    catch{}
    $Disks = $Hardware.LogicalDrives
    foreach ($Disk in $Disks){
        if ($($Disk.Health) -notmatch "HEALTHY"){
            "$($OVCHost.HostName) #Logical Disk $($Disk.Name) - $($Disk.serial_number) is $($Disk.Health)" 
            }
        }
    
    ################################ DISK CHECKS END ################################
    }
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

Function Compare_VM_Lists
{
param (
    $VCList
)
foreach ($VCServer in $VCList){
    $Connection = Connect-VIServer $VCServer -Credential $VCCredential
    $VCClusters = Get-Cluster $SimplivityHost.ClusterName
    foreach ($VCCluster in $VCClusters){
        if ($VCCluster -match "ROBO"){
            #Get the VMs in this Simplivity cluster
            try{$RawSimpClusterVMs = Get-SVTvm -ClusterName $VCCluster.Name | select -expand VMname | sort}
            catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
            #Get the VMs in this VMware cluster
            try{$RawVCClusterVMs = Get-Cluster $VCCluster.Name | get-vm | where {(Get-Datastore -VM $_) -in $SimplivityDatastores.DataStoreName} | select -expand Name | sort}
            catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
            #Records VMs in VC but not on Simplivity
            $MissingVMs = $RawVCClusterVMs | where{$RawSimpClusterVMs -notcontains $_} | where{$_ -notmatch "OmniStackVC"}
            if ($MissingVMs){
                $ErrorList += "$($VCCluster.Name) has the following VMs on vCenter but not showing in Simplivity:`n`r $($MissingVMs)`n`r"
                }
            }
        }       
    }
return $ErrorList
}

Function Find_NonHA_VMs
{
param (
    $HostList
)
foreach ($OVCHost in $HostList){
    try{$RawSimpHostVMs = Get-SVTvm -HostName $OVCHost.HostName | where {$_.State -ne "ALIVE" -or $_.HAstatus -ne "SAFE"} | select vmName,HAstatus}
    catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
    if ($RawSimpHostVMs -ne $null){
        $ErrorList += "The following VMs are not HA-compliant on host $($OVCHost.HostName) :`n $($RawSimpHostVMs.VmName)"
        }
    }
return $ErrorList
}

Function Check_VMHost_Running_Services
{
param (
    $VMHostList
)
foreach ($VMHost in $VMHostList){
    $RUNNINGSERVICES = get-vmhostservice -VMHost $VMHost | where{($_.Running)}
    if ($RUNNINGSERVICES.Key -notcontains "vpxa"){
        "vpxa service not running"
        }
    
    }
}

Function Get_SVT_Backup_Health
{
param (
    $VMList
)
$TimeInPast = ((Get-Date).AddDays(-$MaxDaysSinceBackup)).ToString("dd/MM/yyyy HH:mm")
if ($VMList) {
    foreach ($VM in $VMList){
        $FAILED = $null
        if ($Log) {Write-Logfile "Looking for FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s) since $($TimeInPast)"}
        try{$FAILED=Get-SVTbackup -Vmname $VM -BackupState FAILED -CreatedAfter $TimeInPast}
        catch{if ($Log) {Write-Logfile "$($VM) Did not return any FAILED backups: $($PSItem.ToString())"}}
        if($FAILED){
            write-host "$($FAILED.CreateDate.Count) FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s) since $($TimeInPast)" -ForegroundColor Red
            if ($Log) {Write-Logfile "$($FAILED.CreateDate.Count) FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s) since $($TimeInPast)"}
            "$($FAILED.CreateDate.Count) FAILED backup(s) for $($VM) within last $($MaxDaysSinceBackup) day(s)"
            }
        }
    }
    
}

Function Get_ILO_Health ($HostList,$ShowNoVMs)
{

#"In ILO health function" | out-host
foreach ($OVCHost in $HostList){
    #Let's find the ILO
    $STATUS = $null
    $OVCHostILOIP = $OVCHost
    $ILOConnect=$null
    if ($OVCHostILOIP){
        try{$ILOConnect=Connect-HPEiLO -IP $OVCHostILOIP -Credential $ILOCredential -DisableCertificateAuthentication}
        catch{Write-Output "$(OVCHostILOIP) Ran into an issue: $($PSItem.ToString())"}
        }
    if ($ILOConnect){
    ################################ SERVER INFO CHECKS START ################################
        
        #"Server info"
        $getServerInfo = Get-HPEiLOServerInfo -Connection $ILOConnect 
        foreach($FanInfo in $getServerInfo.FanInfo){
            if ($FanInfo.State -ne "OK"){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) $($FanInfo.Name) is $($FanInfo.State)"
                }
            }
        foreach($TemperatureInfo in $getServerInfo.TemperatureInfo){
            if (($TemperatureInfo.State -notlike "Absent") -And ($TemperatureInfo.State -notlike "OK")){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) $($TemperatureInfo.Name) is $($TemperatureInfo.State)"  
                }
            }
        ################################ SERVER INFO CHECKS END ################################
        
        ################################ ILO HEALTH CHECKS START ################################
        $HealthReport = Get-HPEiLOHealthSummary -Connection $ILOConnect
        foreach($HealthLine in $HealthReport|get-member){
            if ($HealthLine.MemberType -eq “Property” -and $HealthLine.Name -notlike “__*” -and $HealthLine.Name -notlike “IP" -and $HealthLine.Name -notlike “Hostname" -and $($HealthReport.$($HealthLine.Name))){
                switch -regex ($($HealthReport.$($HealthLine.Name)))
                    {
                    "OK" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "Redundant" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "No" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    "Ready" {write-host "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))" -ForegroundColor Green}
                    default {write-warning "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))";$STATUS="RED";$ERRORTEXT += "`n`r$($OVCHost.HostName) $($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}
                    }
                }
            }
        ################################ ILO HEALTH CHECKS END ################################
        
        
        
        ################################ VM CHECKS START ################################
        #"VM checks"
        $VMList = $null
        try{$VMList = Get-SVTvm -hostname $SimplivityHost.HostName} #| select VMname 
        catch{Write-Output "Ran into an issue: $($PSItem.ToString())"}
        if ($ShowNoVMs) {
            if (!($VMList)){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) has no VMs"
                }
            }
        ################################ VM CHECKS START ################################
        
        ################################ ILO IML CHECKS START ################################
        $result = Get-HPEiLOIML -Connection $ILOConnect 
        $TimeInPast = (Get-Date).AddHours(-$MaxHoursToScanLog)
        foreach($output in $result){
            $sevs = $(foreach ($event in $output.IMLLog) {$event.Severity})
            $uniqsev = $($sevs | Sort-Object | Get-Unique)
            $sevcnts = $output.IMLLog | group-object -property Severity –noelement
            $message = $(foreach ($event in $output.IMLLog) {if($event.Severity -eq "Critical" -and $(Get-Date($event.Created)) -gt $TimeInPast) {$($event.Created) + $($event.Message)}})
            $uniqmessage = $($message | Sort-Object | Get-Unique)
            if($uniqmessage -ne $null){
                $allMessage = [string]::Join("`n",$uniqmessage)
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) The critical IML entry descriptions are: `n$allMessage"
                }
        ################################ ILO IML CHECKS END ################################
        
        ################################ ILO EVENT LOG CHECKS START ################################
        $result=$null
        $result = Get-HPEiLOEventLog -Connection $ILOConnect
        foreach($output in $result){
            $sevs = $(foreach ($event in $output.EventLog) {$event.Severity})
            $uniqsev = $($sevs | Sort-Object | Get-Unique)
            $sevcnts = $output.EventLog | group-object -property Severity –noelement
            $message = $(foreach ($event in $output.IMLLog) {if($event.Severity -eq "Critical" -and $(Get-Date($event.Created)) -gt $TimeInPast) {$($event.Created) + $($event.Message)}})
            $uniqmessage = $($message | Sort-Object | Get-Unique)
            if($uniqmessage -ne $null){
                $allMessage = [string]::Join("`n",$uniqmessage)
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($OVCHost) The critical Event entry descriptions are: `n$allMessage"
                }
          
            }
        
        ################################ ILO EVENT LOG CHECKS END ################################
        
        }
        if ($ILOConnect){
            Disconnect-HPEiLO -Connection $ILOConnect
            }
        }
    else{
        $STATUS="RED"
        $ERRORTEXT += "`n`r$($OVCHost) Could not connect to $($OVCHostILO)"
        }
    
    if ($STATUS -ne $null){
        write-host "$($OVCHost) has status $($STATUS)" -ForegroundColor red 
        }
    
    }

return $ERRORTEXT
}

Function get-VCAlarms{
param (
    $HostList
)
$TimeInPast = (Get-Date).AddHours(-$MaxHoursToScanLog)

#Return all alarms for this host that have come after the $MaxHoursToScanLog
$triggeredalarms = (get-datacenter).extensiondata.triggeredalarmstate | where {$_.Time -gt $TimeInPast -and ((Get-View $_.Entity).Name) -match $HostList }


foreach ($triggeredalarm in $triggeredalarms){
    $alarm = "" | Select-Object VC, EntityType, Alarm, Entity, Status, Time, Acknowledged, AckBy, AckTime
  	$alarm.Alarm = (Get-View $triggeredalarm.Alarm).Info.Name
    $alarm.Entity = (Get-View $triggeredalarm.Entity).Name
    $alarm.Status = $triggeredalarm.OverallStatus
  	$alarm.Time = $triggeredalarm.Time
    if ($alarm.Status -eq "red"){
        if ($alarm.Entity -notcontains "OmniStackVC" -and $alarm.Alarm -notcontains "Virtual machine memory usage"){
            "`n`r$($alarm.Entity) has a critical alert ($($alarm.Alarm)) timed at $($alarm.Time)"
            }
        }
    }
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
$ip = $null
[array]$serversummary = @()                                 #Summary of issues found during server health checks
[array]$report = @()
[array]$failreport = @()
[array]$passreport = @()
[bool]$alerts = $false
$servicestatus = "Pass"
$diskstatus = "Pass"
$VCServerList = $global:DefaultVIServers
$ERRORS=$null
$OVC="Not Connected"
$SimplivityHosts=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)


$smtpsettings = @{
    From = $fromaddress
    SmtpServer = $smtpserver
    }

#...................................
# Initialize
#...................................

if (Test-Path "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"){
    del "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " Simplivity Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}

#...................................
# vCenter connection
$Connection = Connect-VIServer $VCServer -Credential $VCCredential -AllLinked


# Grab OVC details
$OVCs = Get-View -ViewType Virtualmachine | where { $_.summary.config.managedby.ExtensionKey -match "com.simplivity.evalta" -and $_.summary.config.managedby.Type -match "omnicube"}
if ($Log) {Write-Logfile "OVC addresses found: $($OVCs.guest.IPAddress)"} 


#...................................

################################ Search for a connection to an Omnistack ####################################
if ($OVCs.guest.IPAddress){

    while($OVC -eq "Not Connected"){
        foreach($OVCIP in $OVCs.guest.IPAddress){ 
            write-host "Trying $($OVCIP)"
            try{$OVC=Connect-SVT -OVC $($OVCIP) -Credential $Credential}
            catch{Write-Output "Ran into an issue: $($PSItem.ToString())"; $ERRORS += "`n`rCould not connect to $($OVCIP) $($PSItem.ToString())";continue}
            if ($OVC){write-host "Connected";break}
            
            }
        } 
    }
#...................................
#Grab Simplivity Hosts and Datastores
$SimplivityHosts = Get-SVThost | sort-object -Property HostName
$SimplivityDatastores = @(Get-SVTdatastore)

#...................................

foreach($SimplivityHost in $SimplivityHosts){ 
    if ($SimplivityHost.HostName -notin $IgnoreHosts){
        Write-Host "Processing $($SimplivityHost.HostName)" -ForegroundColor Blue 
        #Custom object properties
        $serverObj = New-Object PSObject
        $serverObj | Add-Member NoteProperty -Name "Host" -Value $SimplivityHost.HostName
        $serverObj | Add-Member NoteProperty -Name "Cluster" -Value $SimplivityHost.ClusterName
        #Null and n/a the rest, will be populated as script progresses
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Backups" -Value $null
        $serverObj | Add-Member NoteProperty -Name "VMs Match" -Value $null
        $serverObj | Add-Member NoteProperty -Name "HA" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Services" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Network" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "n/a"
    

        #DNS Check
        Write-Host "DNS Check: " -NoNewline;
        try {$ip = @([System.Net.Dns]::GetHostByName($SimplivityHost.HostName).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
        catch {
            Write-Host -ForegroundColor $_.Exception.Message
            $ip = $null
            }
        if ( $ip -ne $null ){
            Write-Host -ForegroundColor $pass "Pass"
            $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
            #Is server online
            Write-Host "Ping Check: " -NoNewline; 
            $ping = $null
            try {$ping = Test-Connection $SimplivityHost.HostName -Quiet -ErrorAction Stop}
            catch {Write-Host -ForegroundColor $warn $_.Exception.Message}

            switch ($ping)
            {
                $true {
                    Write-Host -ForegroundColor $pass "Pass"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                    }
                default {
                    Write-Host -ForegroundColor $fail "Fail"
                    $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                    $serversummary += "$($SimplivityHost.HostName) - Ping Failed"
                    }
                }
            }
        
        #Uptime Check
        Write-Host "Uptime (hrs): " -NoNewline
        [int]$uptimehours = $null
        $vmhost = get-VMhost $SimplivityHost.HostName
        $uptimehours = [math]::round((New-TimeSpan -Start ($vmhost.ExtensionData.Summary.Runtime.BootTime.touniversaltime()) -End (Get-Date -Format U)).TotalHours,0) #| Select-Object -ExpandProperty Days
        if ($uptimehours -lt $MinimumUptime){
           Write-Host -ForegroundColor $warn "Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           $serversummary += "$($SimplivityHost.HostName) - Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           }
        else{
            Write-Host -ForegroundColor $pass "Uptime is more than $($MinimumUptime) hours ($($uptimehours))"
            }
        
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 

        #Backup Check (make this host specific)
        Write-Host "SVT Backups: " -NoNewline
        $VMList = (Get-SVTvm -HostName $SimplivityHost.HostName  | where{$_ -notmatch "OmniStackVC"} | Select -ExpandProperty VMname) 
        $ERRORS = $null
        $ERRORS += Get_SVT_Backup_Health $VMList
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Pass" -Force }
            $false { Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($SimplivityHost.HostName) - Simplivity Backup Error(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Fail" -Force }
            default { Write-Host -ForegroundColor $fail "Default"; $serversummary += "$($SimplivityHost.HostName) - Simplivity Backup Error(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Backups" -Value "Fail" -Force}
            }
    
        #VM Match Check
        Write-Host "VM Match Check: " -NoNewline
        $ERRORS = $null
        $ERRORS += Compare_VM_Lists $VCServer
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "VMs Match" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity VM Mismatch(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "VMs Match" -Value "Fail" -Force}
            }
    
    
        #HA VM Check
        Write-Host "VM HA Check: " -NoNewline
        $ERRORS = $null
        $ERRORS += Find_NonHA_VMs $SimplivityHost
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity VM HA $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "HA" -Value "Fail" -Force}
            }
   
    
        #VC Alarms
        Write-Host "Host Alarms: " -NoNewline
        $ERRORS = $null
        $ERRORS += get-VCAlarms $SimplivityHost.HostName
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Host Alarm(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Fail" -Force}
            }
        Write-Host "OVC Alarms: " -NoNewline
        $ERRORS = $null
        $ERRORS += get-VCAlarms $SimplivityHost.VirtualControllerName
        $ERRORS | fl
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.VirtualControllerName) - Simplivity OVC Alarm(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value "Fail" -Force}
            }
    
        #Host Services
        Write-Host "Host Services: " -NoNewline
        $ERRORS = $null
        $ERRORS +=  Check_VMHost_Running_Services $SimplivityHost.HostName
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Service(s) $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Fail" -Force}
            }

        #Network
        Write-Host "Network: " -NoNewline
        $NetworkOK = $true
        #Ping the OVC
        $ip =(Get-VM -Name $SimplivityHost.VirtualControllerName | select @{N="IPAddress";E={@($_.guest.IPAddress[0])}}).IPAddress
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
            $serversummary += "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable;"
            if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable"}
            write-host "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is not pingable"
            }
        else{
            if ($Log) {Write-Logfile "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is pingable"}
            write-host "$($SimplivityHost.HostName) -  OVC interface at address $($ip) is pingable"
            }
    
    
        Switch ($NetworkOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Network" -Value "Pass" -Force}
                $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
                }
        #ILO Health
        Write-Host "Host Hardware: " -NoNewline
        $ERRORS = $null
        if ($SimplivityHost.HostName -in $IgnoreHardwareErrors){
            if ($Log) {Write-Logfile "Host in $($IgnoreHardwareErrors) array - Not checking for hardware errors on $($SimplivityHost.HostName)"}
            $ERRORS = $null
            Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force
            } 
        else{
            #This function when servers are new and you want to see hosts with no VMs 
            #This function when servers are established and you don't want to see hosts with no VMs 
            $esxcli = Get-VMHost $VMHost | Get-EsxCLI -V2
            $ESXiVersion = $null
            $ESXiVersion = $esxcli.system.version.get.Invoke()
            if ($Log) {Write-Logfile "Build is $($ESXiVersion.Build)"}
            if ($Log) {Write-Logfile "Patch is $($ESXiVersion.Patch)"}
            if ($Log) {Write-Logfile "Product is $($ESXiVersion.Product)"}
            if ($Log) {Write-Logfile "Update is $($ESXiVersion.Update)"}
            if ($Log) {Write-Logfile "Version is $($ESXiVersion.Version)"}
            $IPMI = $esxcli.hardware.ipmi.bmc.get.Invoke()
            if ($Log) {Write-Logfile "IPMI address is $($IPMI.IPv4Address)"}
            if ($Log) {Write-Logfile "IPMI manufacturer is $($IPMI.Manufacturer)"}
            $ERRORS += Get_ILO_Health $IPMI.IPv4Address $False
            $ERRORS
            Switch (!$ERRORS) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Hardware $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
                }
            }
        #Disk Space
        Write-Host "Disk Space: " -NoNewline
        $ERRORS = $null
        $ERRORS += Get_DiskSpace $SimplivityHost $False
        $ERRORS
        Switch (!$ERRORS) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $ERRORS; $serversummary += "$($SimplivityHost.HostName) - Simplivity Disk Space $($ERRORS)";$serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Fail" -Force}
            }
        #Add this servers output to the $report array
        $report = $report + $serverObj
    
        }         

    else{
        Write-Host "Ignoring $($SimplivityHost.HostName)" -ForegroundColor Blue
        } 
    }
### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    if ($IgnoreHosts){
        $ignoretext = "Configured to ignore hosts: $($IgnoreHosts)."
        }
    if ($IgnoreHardwareErrors){
        $ignoretext = $ignoretext + "Configured to ignore hardware errors on : $($IgnoreHardwareErrors)."
        }
    #Create HTML Report
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\Simplivity_Error_Status_Fail.txt"
        
        #Generate the HTML
        $coloredheader = "<h1 align=""center""><a href=$ReportURL  class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>Simplivity Health Details</h3>
                        <p>$ignoretext</p>
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
        $serversummaryhtml = "<h3>Simplivity Health Details</h3>
                        <p>$ignoretext</p>
                        <p>No Simplivity  health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>Simplivity GreenScreen - $servicestatus</title>
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
                tr:nth-child(even){Background-Color: rgb(110, 122, 130);}
                th{Text-Align: Left;Color: rgb(150, 150, 220);Padding: 1px 4px 1px 4px;}
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

        
    #Simplivity Health Report Table Header
    $htmltableheader = "<h3>Simplivity Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Host</th>
                        <th>Cluster</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>Backups</th>
                        <th>VMs Match</th>
                        <th>HA</th>
                        <th>Host Alarms</th>
                        <th>OVC Alarms</th>
                        <th>Services</th>
                        <th>Network</th>
                        <th>Hardware</th>
                        <th>Disk Space</th>
                        </tr>"

    #Simplivity Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader                    
                        
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        if (($line -match "Fail") -or ($line -match "Warn") -or ($line."uptime (hrs)" -lt $MinimumUptime) ){
            write-host "$($line.host) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.host) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }
    
    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "dns")
        $htmltablerow += (New-ServerHealthHTMLTableCell "ping")
        
        if ($($reportline."uptime (hrs)") -eq "Access Denied")
        {
            $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        }
        elseif ($($reportline."uptime (hrs)") -eq "Unable to retrieve uptime. ")
        {
            $htmltablerow += "<td class=""warn"">Unable to retrieve uptime. </td>"
        }
        else
        {
            $hours = [int]$($reportline."uptime (hrs)")
            if ($hours -lt $MinimumUptime)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "Backups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs Match")
        $htmltablerow += (New-ServerHealthHTMLTableCell "HA")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "OVC Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Network")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    }

    #Add passes after so they show up last
    foreach ($reportline in $passreport)
    {
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += "<td>$($reportline.cluster)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "dns")
        $htmltablerow += (New-ServerHealthHTMLTableCell "ping")
        
        if ($($reportline."uptime (hrs)") -eq "Access Denied")
        {
            $htmltablerow += "<td class=""warn"">Access Denied</td>"        
        }
        elseif ($($reportline."uptime (hrs)") -eq "Unable to retrieve uptime. ")
        {
            $htmltablerow += "<td class=""warn"">Unable to retrieve uptime. </td>"
        }
        else
        {
            $hours = [int]$($reportline."uptime (hrs)")
            if ($hours -lt $MinimumUptime)
            {
                $htmltablerow += "<td class=""warn"">$hours</td>"
            }
            else
            {
                $htmltablerow += "<td class=""pass"">$hours</td>"
            }
        }

        $htmltablerow += (New-ServerHealthHTMLTableCell "Backups")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs Match")
        $htmltablerow += (New-ServerHealthHTMLTableCell "HA")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "OVC Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Network")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
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

