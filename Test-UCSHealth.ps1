<#
.SYNOPSIS
Test-UCSHealth.ps1 - UCS Health Check Script.

.DESCRIPTION 
Performs a series of health checks on UCS  and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.EXAMPLE
.\Test-UCSHealth.ps1 -ConfigFile C:\Source\Scripts\cisco\ucs\test-ucshealth-cfg.ps1
Checks all UCS systems in the organization and outputs the results to the shell window.

.LINK

github\kevinsnook

.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on UCS systems and reports them on a Pass/Fail basis.
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

#This function is used to write the log file if Log variable in config file is used
Function Write-Logfile()
{
    param( $logentry )
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logentry" | Out-File $logfile -Append
}


#...................................
# Script
#...................................

#Find run directory 
$runDir = Split-Path -Parent $MyInvocation.MyCommand.Path


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
if (Test-Path "$($OutputFolder)\UCSHealth_errors.html" -PathType Leaf){
    del "$($OutputFolder)\UCSHealth_errors.html"
    }
$SystemErrors = $false                                    #Variable to show whether system errors have been encountered on any node
$AlertSeverity = "warning"                               #Variable to pick which system errors to pick up: warning, error, critical, debug, informational, notice

#Times on UCSE are held in GMT (UTC) - so let's work out current offset to GMT
$tz = Get-CimInstance win32_timezone
$GMTOffsetMinutes = ($tz.Bias + $tz.DaylightBias)
$GMTOffsetMinutes
#exit


#...................................
# Email Settings
#...................................

    $smtpsettings = @{
    From = $fromaddress
    SmtpServer = $smtpserver
    }

#...................................
# Initialize
#...................................

if (Test-Path "$($OutputFolder)\UCS_Error_Status_Fail.txt"){
    del "$($OutputFolder)\UCS_Error_Status_Fail.txt"
    }

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " UCS  Systems Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


#...................................
# Credentials
#...................................



foreach ($UCSMServer in $UCSMServers){ 
    Disconnect-Ucs
    if ($Log) {Write-Logfile "Processing controller $($UCSMServer)"}
    $UCSMConnection = $null
    $UCSMConnection = Connect-Ucs $UCSMServer -Credential $UCSCredential
    if ($UCSMConnection){
        #Times on UCS are held in GMT (UTC) - so let's work out current offset to GMT
        $tz = Get-CimInstance win32_timezone
        $GMTOffsetMinutes = ($tz.Bias + $tz.DaylightBias)
        

        $FirstLogEntry = get-ucsevent | select -first 1
        [datetime]$FirstLogEntryCreated = $FirstLogEntry.Created
        $DefaultSPuptimehours = $DefaultServeruptimehours = ([math]::round((New-TimeSpan -Start $FirstLogEntryCreated -End (Get-Date)).TotalHours,0)).tostring() + "+"
    
        if ($Log) {Write-Logfile "Log file started: $($FirstLogEntryCreated)"}
        $LogFileTimeSpan = [math]::round((New-TimeSpan -Start $FirstLogEntryCreated -End (Get-Date)).TotalHours,0)
        if ($Log) {Write-Logfile "Log file started $($LogFileTimeSpan) hours ago"}
        $serviceprofiles = get-ucsserviceprofile -type instance | where {$_.AssignState -notmatch "unassigned" -and $_.AssocState -notmatch "unassociated"}
        $serviceprofiles
        #--- External Mgmt IP Pool ---#
	    if ($Log) {Write-Logfile "Find assigned KVM addresses:"}
        $Mgmt_IP_Pool = @{}

	    #--- Get the default external management pool ---#
	    $mgmtPool = Get-ucsippoolblock -Ucs $UCSMConnection -Filter "Dn -cmatch ext-mgmt"
        $parentPool = $mgmtPool | get-UcsParent
        $Mgmt_IP_Allocation = @()
        $parentPool | Get-UcsIpPoolPooled -Filter "Assigned -ieq yes" | Select AssignedToDn,Id,Subnet,DefGw | % {
		    $mgmtIpObj = New-Object psobject
		    if ($Log) {Write-Logfile "assignedDN is $($_.AssignedToDn)"}
            $DN = $_.AssignedToDn -replace "/mgmt/*.*", ""
            if ($DN -match "org-root"){
                if ($Log) {Write-Logfile "It's a SP-derived management address"}
                #The name of the SP is between ls- and /ipv4-pooled-addr
                $DNArray = $DN -split "ls-"
                $DN = $DNArray[1] -replace "/ipv4-pooled-addr","" 
            
                }
            else{
                #The name of the hardware after sys/
                $DN = $DN -replace "sys/",""
            
                }
            if ($Log) {Write-Logfile "DN is $($DN)"}
            $mgmtIpObj | Add-Member -Name AssignedtoDN -MemberType NoteProperty -Value $_.AssignedToDn
            if ($Log) {Write-Logfile "Assigned DN is $($_.AssignedToDn)"}
            $mgmtIpObj | Add-Member -Name DN -MemberType NoteProperty -Value $DN
            if ($Log) {Write-Logfile "DN is $($DN)"}
            $mgmtIpObj | Add-Member -Name IP -MemberType NoteProperty -Value $_.Id
            if ($Log) {Write-Logfile "IP address is $($_.Id)"}
		    $Mgmt_IP_Allocation += $mgmtIpObj
	        }
        
        foreach ($serviceprofile in $serviceprofiles){
            #"Service Profile is $($serviceprofile.Name)"
            $ServiceProfileIPAllocation = $Mgmt_IP_Allocation | where {$_.AssignedtoDN -match $serviceprofile.DN}
            $MachineIPAllocation = $Mgmt_IP_Allocation | where {$_.AssignedtoDN -match $serviceprofile.PnDn}
            if ($Log) {Write-Logfile "Management IP for service profile $($serviceprofile.Name) is $($ServiceProfileIPAllocation.IP)"}
            if ($Log) {Write-Logfile "Management IP for machine $($serviceprofile.PnDn) is $($MachineIPAllocation.IP)"}
            }
       
        $UCSStatus = Get-UcsStatus
        $UCSStatus #| gm
        $FICOK = $true
        if ($Log) {Write-Logfile "Status for $($UCSStatus.Name)"}
        if ($Log) {Write-Logfile "VirtualIpv4Address is $($UCSStatus.VirtualIpv4Address)"}
        if ($Log) {Write-Logfile "HaReadiness is $($UCSStatus.HaReadiness)"}
        if ($UCSStatus.HaReadiness -notmatch "ready"){
            $FICOK = $false
            }
        if ($Log) {Write-Logfile "HaReady is $($UCSStatus.HaReady)"}
        if ($UCSStatus.HaReady -notmatch "yes"){
            $FICOK = $false
            }
        if ($Log) {Write-Logfile "EthernetState is $($UCSStatus.EthernetState)"}
        if ($UCSStatus.EthernetState -notmatch "full"){
            $FICOK = $false
            }
        if ($Log) {Write-Logfile "Chassis1Status is $($UCSStatus.Chassis1Status)"}
        if ($UCSStatus.Chassis1Status -notmatch "ok"){
            $FICOK = $false
            }
        if ($Log) {Write-Logfile "Chassis2Status is $($UCSStatus.Chassis2Status)"}
        if ($UCSStatus.Chassis2Status -notmatch "ok"){
            $FICOK = $false
            }
        
        #Get the two OOB addresses (not the VIP)
        if ($Log) {Write-Logfile "FIC A OOB address is $($UCSStatus.FiAOobIpv4Address)"}
        if ($Log) {Write-Logfile "FIC B OOB address is $($UCSStatus.FiBOobIpv4Address)"}
        #Are both FICs up
        if ($Log) {Write-Logfile "FIC A services are $($UCSStatus.FiAManagementServicesState)"}
        if ($UCSStatus.FiAManagementServicesState -notmatch "up"){
            $FICOK = $false
            }
        if ($Log) {Write-Logfile "FIC B services are $($UCSStatus.FiBManagementServicesState)"}
        if ($UCSStatus.FiBManagementServicesState -notmatch "up"){
            $FICOK = $false
            }
        #Ping each OOB address
        $OOBAddresses = @($UCSStatus.VirtualIpv4Address,$UCSStatus.FiAOobIpv4Address,$UCSStatus.FiBOobIpv4Address)
        foreach ($OOBAddress in $OOBAddresses){
            if ($OOBAddress -ne $null){
                    if ($Log) {Write-Logfile "Ping check for OOB IP $($OOBAddress)"}
                    $ping = $null
                    try {$ping = Test-Connection $OOBAddress -Quiet -ErrorAction Stop}
                    catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                        if ($Log) {Write-Logfile "$_.Exception.Message"}
                        }
                    if (!$ping) {
                    $FICOK = $false
                    if ($OOBAddress -ne "0.0.0.0"){
                        $serversummary += "$($UCSMConnection.Ucs) -  interface at address $($OOBAddress) is not pingable;"
                        if ($Log) {Write-Logfile "$($UCSMConnection.Ucs) -  interface at address $($OOBAddress) is not pingable"}
                        $FICOK = $false
                        }
                    else {
                        $serversummary += "$($UCSMConnection.Ucs) -  cannot find IP for management interface;"
                        if ($Log) {Write-Logfile "$($UCSMConnection.Ucs) -  cannot find IP for management interface;"}
                        $FICOK = $false
                        }      
                     }
                else{
                    if ($Log) {Write-Logfile "$($UCSMConnection.Ucs) -  interface at address $($OOBAddress) is pingable"}
                    }
                }
            }    
        #Find all faults specific to this FIC
        $FICFaults = get-ucsfault |where {$_.Severity -notin (“cleared","condition","info","warning","minor") -and $_.Dn -notlike "*sys/rack-unit*"  -and $_.Dn -notlike "*sys/chassis*"}
    

        if ($FICFaults){
            foreach ($FICFault in $FICFaults){
                
                if ($Log) {Write-Logfile "Looking for $IgnoreObjects elements in $($FICFault.Descr)"}
                if ($null -ne ($IgnoreObjects | where { $FICFault.Descr -like $_ })){  
                    if ($Log) {Write-Logfile "Found partial match of $IgnoreObjects element in $($FICFault.Descr)"}
                    }    
                else{
                    $serversummary += "$($UCSMConnection.Ucs) -  $($FICFault.Descr);"
                    if ($Log) {Write-Logfile "$($UCSMConnection.Ucs) -  $($FICFault.Descr);"}
                    if ($Log) {Write-Logfile $FICFault.Ack}
                    if ($Log) {Write-Logfile $FICFault.Cause}
                    if ($Log) {Write-Logfile $FICFault.ChangeSet}
                    if ($Log) {Write-Logfile $FICFault.Code}
                    if ($Log) {Write-Logfile $FICFault.Created}
                    if ($Log) {Write-Logfile $FICFault.Descr}
                    if ($Log) {Write-Logfile $FICFault.HighestSeverity}
                    if ($Log) {Write-Logfile $FICFault.Id}
                    if ($Log) {Write-Logfile $FICFault.LastTransition}
                    if ($Log) {Write-Logfile $FICFault.Lc}
                    if ($Log) {Write-Logfile $FICFault.Occur}
                    if ($Log) {Write-Logfile $FICFault.OrigSeverity}
                    if ($Log) {Write-Logfile $FICFault.PrevSeverity}
                    if ($Log) {Write-Logfile $FICFault.Rule}
                    if ($Log) {Write-Logfile $FICFault.Sacl}
                    if ($Log) {Write-Logfile $FICFault.Severity}
                    if ($Log) {Write-Logfile $FICFault.Tags}
                    if ($Log) {Write-Logfile $FICFault.Type}
                    if ($Log) {Write-Logfile $FICFault.Ucs}
                    if ($Log) {Write-Logfile $FICFault.Dn}
                    if ($Log) {Write-Logfile $FICFault.Rn}
                    if ($Log) {Write-Logfile $FICFault.Status}
                    $FICOK = $false
                    }
                }
            
            }
        #exit
        #Find which is primary/secondary
        if ($UCSStatus.FiALeadership -match "primary"){
            if ($Log) {Write-Logfile "FIC A is primary, FIC B is subordinate"}
            }           
        else{
            if ($Log) {Write-Logfile "FIC B is primary, FIC A is subordinate"}
            }

      
        $UCSFiModules = Get-UcsFiModule
        foreach ($UCSFiModule in $UCSFiModules){
            if ($UCSFiModule.Dn -match "switch-A"){
                write-host "Fabric Interconnect A" -ForegroundColor Yellow
                }
            else{
                write-host "Fabric Interconnect B" -ForegroundColor Yellow
                }
            
            }

    
        #Keyring check
        $UCSTrustPoint = Get-UCSTrustPoint
        if ($UCSTrustPoint.CertStatus -eq "valid"){
            write-host "TP Certificate is valid"
            }
        
        $UCSHTTPKeyring = Get-UcsHttps | select Keyring
        write-host "Keyring used is $($UCSHTTPKeyring.Keyring)"
        $UCSKeyRing = Get-UcsKeyRing -Name $UCSHTTPKeyring.Keyring
        if ($UCSKeyRing.ConfigState -eq "ok"){
            write-host "Keyring Configstate is OK"
            if ($UCSKeyRing.CertStatus -eq "valid"){
                write-host "Keyring Certificate is valid"
                }
            else{
                write-host "Keyring Certificate is not valid"
                }
            }
        else{
            write-host "Keyring Configstate is not OK"
            }
    
    
        
        if ($Log) {Write-Logfile "Processing UCS system $($UCSMConnection.Ucs) running version $($UCSMConnection.Version)"}
    
        #Get chassis connected to this FIC
        $chassiss = Get-UcsChassis
        foreach ($chassis in $chassiss){
            $chassisfaults = $chassis| get-ucsfault |where {$_.Descr -like “*inoperable*” -or $_.Descr -like “*FAILED*” -and $_.Descr -notlike “*server*” -and $_.Severity -notin (“cleared","condition","info","warning","minor")}
            if ($chassisfaults){
                foreach ($chassisfault in $chassisfaults){
                    write-host $chassisfault.Descr -ForegroundColor Red
                    $serversummary += "Chassis fault $($chassis.Rn): $($chassisfault.Descr)"
                    if ($Log) {Write-Logfile $chassisfault.Ack}
                    if ($Log) {Write-Logfile $chassisfault.Cause}
                    if ($Log) {Write-Logfile $chassisfault.ChangeSet}
                    if ($Log) {Write-Logfile $chassisfault.Code}
                    if ($Log) {Write-Logfile $chassisfault.Created}
                    if ($Log) {Write-Logfile $chassisfault.Descr}
                    if ($Log) {Write-Logfile $chassisfault.HighestSeverity}
                    if ($Log) {Write-Logfile $chassisfault.Id}
                    if ($Log) {Write-Logfile $chassisfault.LastTransition}
                    if ($Log) {Write-Logfile $chassisfault.Lc}
                    if ($Log) {Write-Logfile $chassisfault.Occur}
                    if ($Log) {Write-Logfile $chassisfault.OrigSeverity}
                    if ($Log) {Write-Logfile $chassisfault.PrevSeverity}
                    if ($Log) {Write-Logfile $chassisfault.Rule}
                    if ($Log) {Write-Logfile $chassisfault.Sacl}
                    if ($Log) {Write-Logfile $chassisfault.Severity}
                    if ($Log) {Write-Logfile $chassisfault.Tags}
                    if ($Log) {Write-Logfile $chassisfault.Type}
                    if ($Log) {Write-Logfile $chassisfault.Ucs}
                    if ($Log) {Write-Logfile $chassisfault.Dn}
                    if ($Log) {Write-Logfile $chassisfault.Rn}
                    if ($Log) {Write-Logfile $chassisfault.Status}
                    }
                }
            }
    
    

        

        #Get servers connected to this FIC
        $UCSservers = Get-UcsServer | sort -property Dn | where{$_.Association -eq "associated"}
        foreach ($UCSserver in $UCSservers){
            $UCSServerID = $UCSServer.DN.replace("sys/","")
            $Server2BIgnored = $false
            foreach ($IgnoreServerID in $IgnoreServerIDs){
                $IgnoreServerFIC = ($IgnoreServerID  -split '@')[1]
                $IgnoreServer = ($IgnoreServerID  -split '@')[0]
                if (($IgnoreServerFIC -like $UCSMConnection.Ucs) -and ($IgnoreServer -like $UCSServerID))
                    {
                    $Server2BIgnored = $true
                    }
                }
            if (!$Server2BIgnored){
                if ($Log) {Write-Logfile "ServerID $($UCSserver.ServerId)"}
                if ($Log) {Write-Logfile "Association is $($UCSserver.Association)"}
                if ($Log) {Write-Logfile "CheckPoint is $($UCSserver.CheckPoint)"}
                if ($Log) {Write-Logfile "ConnPath is $($UCSserver.ConnPath)"}
                if ($Log) {Write-Logfile "ConnStatus is $($UCSserver.ConnStatus)"}
                if ($Log) {Write-Logfile "Discovery is $($UCSserver.Discovery)"}
                if ($Log) {Write-Logfile "EnclosureId is $($UCSserver.EnclosureId)"}
                if ($Log) {Write-Logfile "Id is $($UCSserver.Id)"}
                if ($Log) {Write-Logfile "KmipFault is $($UCSserver.KmipFault)"}
                if ($Log) {Write-Logfile "KmipFaultDescription is $($UCSserver.KmipFaultDescription)"}
                if ($Log) {Write-Logfile "Lc is $($UCSserver.Lc)"}
                if ($Log) {Write-Logfile "ManagingInst is $($UCSserver.ManagingInst)"}
                if ($Log) {Write-Logfile "Model is $($UCSserver.Model)"}
                if ($Log) {Write-Logfile "Name is $($UCSserver.Name)"}
                if ($Log) {Write-Logfile "OperState is $($UCSserver.OperState)"}
                if ($Log) {Write-Logfile "Operability is $($UCSserver.Operability)"}
                if ($Log) {Write-Logfile "Presence is $($UCSserver.Presence)"}
                if ($Log) {Write-Logfile "SlotId is $($UCSserver.SlotId)"}
                if ($Log) {Write-Logfile "UsrLbl is $($UCSserver.UsrLbl)"}
                if ($Log) {Write-Logfile "VethStatus is $($UCSserver.VethStatus)"}
                if ($Log) {Write-Logfile "Ucs is $($UCSserver.Ucs)"}
                if ($Log) {Write-Logfile "Dn is $($UCSserver.Dn)"}
                if ($Log) {Write-Logfile "Rn is $($UCSserver.Rn)"}
        
                $serverIdentity = $UCSserver.Dn -Replace "sys/",""
                $serviceprofile = $serviceprofiles | where{$_.PnDn -eq $UCSserver.Dn}
                write-host "ServerID $($serverIdentity)" -ForegroundColor Yellow

                #Custom object properties
                $serverObj = New-Object PSObject
                $serverObj | Add-Member NoteProperty -Name "UCSSystem" -Value $UCSMConnection.Ucs
                #Null and n/a the rest, will be populated as script progresses
                $serverObj | Add-Member NoteProperty -Name "Service Profile" -Value $serviceprofile.Name
                $serverObj | Add-Member NoteProperty -Name "Blade/Server" -Value $serverIdentity       
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
                $serverObj | Add-Member NoteProperty -Name "System" -Value $null
                $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
                $serverObj | Add-Member NoteProperty -Name "Faults" -Value $null
                $serverObj | Add-Member NoteProperty -Name "Networks" -Value $null
                $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"

               write-host "System:" -nonewline
                if (!$FICOK){
                    Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "System" -Value "Fail" -Force
                
                    }
                else{
                    Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "System" -Value "Pass" -Force
                    }
        
            
                write-host "Hardware:" -nonewline
                        
                $serverfaults = $UCSserver | get-ucsfault |where {$_.Descr -like “*inoperable*” -and $_.Severity -notin (“cleared","condition","info","warning","minor")}
        
                if ($serverfaults){
                    foreach ($serverfault in $serverfaults){
                        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force
                        write-host $serverfault.Descr -ForegroundColor Red
                        $serversummary += "$($serverIdentity) - $($serverfault.Descr)"
                        if ($Log) {Write-Logfile $serverfault.Ack}
                        if ($Log) {Write-Logfile $serverfault.Cause}
                        if ($Log) {Write-Logfile $serverfault.ChangeSet}
                        if ($Log) {Write-Logfile $serverfault.Code}
                        if ($Log) {Write-Logfile $serverfault.Created}
                        if ($Log) {Write-Logfile $serverfault.Descr}
                        if ($Log) {Write-Logfile $serverfault.HighestSeverity}
                        if ($Log) {Write-Logfile $serverfault.Id}
                        if ($Log) {Write-Logfile $serverfault.LastTransition}
                        if ($Log) {Write-Logfile $serverfault.Lc}
                        if ($Log) {Write-Logfile $serverfault.Occur}
                        if ($Log) {Write-Logfile $serverfault.OrigSeverity}
                        if ($Log) {Write-Logfile $serverfault.PrevSeverity}
                        if ($Log) {Write-Logfile $serverfault.Rule}
                        if ($Log) {Write-Logfile $serverfault.Sacl}
                        if ($Log) {Write-Logfile $serverfault.Severity}
                        if ($Log) {Write-Logfile $serverfault.Tags}
                        if ($Log) {Write-Logfile $serverfault.Type}
                        if ($Log) {Write-Logfile $serverfault.Ucs}
                        if ($Log) {Write-Logfile $serverfault.Dn}
                        if ($Log) {Write-Logfile $serverfault.Rn}
                        if ($Log) {Write-Logfile $serverfault.Status}
                        }
                    Write-Host -ForegroundColor $fail "Fail"
                    }
       
                else{
                    Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force
            
                    }  
        
                write-host "Networks:" -nonewline
                
                $serverfaults = $null
                $serverfaults = $UCSserver | get-ucsfault | where {$_.Type -match “network” -and $_.Severity -notin (“cleared","condition","info","warning","minor")}
                
                if ($serverfaults){
                    foreach ($serverfault in $serverfaults){
                        $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force
                        write-host $serverfault.Descr -ForegroundColor Red
                        $serversummary += "$($serverIdentity) - $($serverfault.Descr)"
                        if ($Log) {Write-Logfile $serverfault.Ack}
                        if ($Log) {Write-Logfile $serverfault.Cause}
                        if ($Log) {Write-Logfile $serverfault.ChangeSet}
                        if ($Log) {Write-Logfile $serverfault.Code}
                        if ($Log) {Write-Logfile $serverfault.Created}
                        if ($Log) {Write-Logfile $serverfault.Descr}
                        if ($Log) {Write-Logfile $serverfault.HighestSeverity}
                        if ($Log) {Write-Logfile $serverfault.Id}
                        if ($Log) {Write-Logfile $serverfault.LastTransition}
                        if ($Log) {Write-Logfile $serverfault.Lc}
                        if ($Log) {Write-Logfile $serverfault.Occur}
                        if ($Log) {Write-Logfile $serverfault.OrigSeverity}
                        if ($Log) {Write-Logfile $serverfault.PrevSeverity}
                        if ($Log) {Write-Logfile $serverfault.Rule}
                        if ($Log) {Write-Logfile $serverfault.Sacl}
                        if ($Log) {Write-Logfile $serverfault.Severity}
                        if ($Log) {Write-Logfile $serverfault.Tags}
                        if ($Log) {Write-Logfile $serverfault.Type}
                        if ($Log) {Write-Logfile $serverfault.Ucs}
                        if ($Log) {Write-Logfile $serverfault.Dn}
                        if ($Log) {Write-Logfile $serverfault.Rn}
                        if ($Log) {Write-Logfile $serverfault.Status}
                        }
                    Write-Host -ForegroundColor $fail "Fail"
                    }
       
                else{
                    Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Pass" -Force
                    }  
        
            
        
                write-host "Uptime:" -nonewline
                
                $ComputeReboot = $null
                $ComputeReboot = Get-UcsManagedObject -ClassId ComputeRebootLog | where {$_.Dn -match $UCSserver.Dn } | Sort-Object TimeStamp | select -Last 1 | select PwrChangeSrc,TimeStamp
                [datetime]$ServerBootTime = $ComputeReboot.TimeStamp
                if ($Log) {Write-Logfile "Original timestamp:$($ServerBootTime)"}
                [datetime]$ServerBootTime = $ServerBootTime.AddMinutes(-$GMTOffsetMinutes)
                if ($Log) {Write-Logfile "Adjusted timestamp:$($ServerBootTime)"}
                if ($Log) {Write-Logfile "Server Last Power Transition ($($ComputeReboot.PwrChangeSrc)): $($ServerBootTime)"}
                $Serveruptimehours = $null
                $Serveruptimehours = [math]::round((New-TimeSpan -Start $ServerBootTime -End (Get-Date).AddMinutes(-$GMTOffsetMinutes)).TotalHours,0)
                write-host "Server Uptime: $($Serveruptimehours)" 
                if ($Log) {Write-Logfile "Server Uptime: $($Serveruptimehours)"}
                
                if ($Serveruptimehours -lt $MinimumUptime){
                   Write-Host -ForegroundColor $warn "Uptime is less than $($MinimumUptime) hours ($($Serveruptimehours))"
                   $serversummary += "$($serverIdentity) - Uptime is less than $($MinimumUptime) hours ($($Serveruptimehours))"
                   }
                else{
                    Write-Host -ForegroundColor $pass "Uptime is more than $($MinimumUptime) hours ($($Serveruptimehours))"
                    }

                $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $Serveruptimehours -Force 

                write-host "Faults:" -nonewline
                #Get all faults not in the network or hardware sections
                $serverfaults = $null
                $serverfaults = $UCSserver | get-ucsfault | where {$_.Descr -notlike “*inoperable*” -and $_.Type -notmatch “network” -and $_.Severity -notin (“cleared","condition","info","warning","minor")}
           
               if ($serverfaults){
                    foreach ($serverfault in $serverfaults){
                        $serverObj | Add-Member NoteProperty -Name "Faults" -Value "Fail" -Force
                        write-host $serverfault.Descr -ForegroundColor Red
                        $serversummary += "$($serverIdentity) - $($serverfault.Descr)"
                        if ($Log) {Write-Logfile $serverfault.Ack}
                        if ($Log) {Write-Logfile $serverfault.Cause}
                        if ($Log) {Write-Logfile $serverfault.ChangeSet}
                        if ($Log) {Write-Logfile $serverfault.Code}
                        if ($Log) {Write-Logfile $serverfault.Created}
                        if ($Log) {Write-Logfile $serverfault.Descr}
                        if ($Log) {Write-Logfile $serverfault.HighestSeverity}
                        if ($Log) {Write-Logfile $serverfault.Id}
                        if ($Log) {Write-Logfile $serverfault.LastTransition}
                        if ($Log) {Write-Logfile $serverfault.Lc}
                        if ($Log) {Write-Logfile $serverfault.Occur}
                        if ($Log) {Write-Logfile $serverfault.OrigSeverity}
                        if ($Log) {Write-Logfile $serverfault.PrevSeverity}
                        if ($Log) {Write-Logfile $serverfault.Rule}
                        if ($Log) {Write-Logfile $serverfault.Sacl}
                        if ($Log) {Write-Logfile $serverfault.Severity}
                        if ($Log) {Write-Logfile $serverfault.Tags}
                        if ($Log) {Write-Logfile $serverfault.Type}
                        if ($Log) {Write-Logfile $serverfault.Ucs}
                        if ($Log) {Write-Logfile $serverfault.Dn}
                        if ($Log) {Write-Logfile $serverfault.Rn}
                        if ($Log) {Write-Logfile $serverfault.Status}
                        }
                    Write-Host -ForegroundColor $fail "Fail"
                    }
       
                else{
                    Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Faults" -Value "Pass" -Force
                    }  
        
                write-host "Ping:" -nonewline
                #Get the management IP for this blade/server and ping
        
                if ($Log) {Write-Logfile "UCS Hardware: $($UCSserver.Dn)"}
                if ($Log) {Write-Logfile "Service Profile: $($serviceprofile.PnDn)"}
                $ServiceProfileIPAllocation = $Mgmt_IP_Allocation | where {$_.AssignedtoDN -match $serviceprofile.DN}
                if ($Log) {Write-Logfile "ServiceProfileIPAllocation: $($ServiceProfileIPAllocation)"}
                $MachineIPAllocation = $null
                $MachineIPAllocation = $Mgmt_IP_Allocation | where {$_.AssignedtoDN -match $serviceprofile.PnDn} 
                if ($serviceprofile.PnDn){
                    if ($Log) {Write-Logfile "MachineIPAllocation: $($MachineIPAllocation)"}   
                    $MachineIP = $MachineIPAllocation.IP
                    if ($Log) {Write-Logfile "Machine IP: $($MachineIPAllocation.IP)"}
                    $ServiceProfileIP = $ServiceProfileIPAllocation.IP
                    if ($Log) {Write-Logfile "Service Profile IP: $($ServiceProfileIPAllocation.IP)"}
                    #Try and ping each management address 
                    $PingOK = $true
                    if ($ServiceProfileIP -ne $null -and $ServiceProfileIP -ne "0.0.0.0" -and $MachineIP -ne $null -and $MachineIP -ne "0.0.0.0"){
                        if ($ServiceProfileIP -ne $null){
                            if ($Log) {Write-Logfile "Ping check for Service Profile IP"}
                            $ping = $null
                            try {$ping = Test-Connection $ServiceProfileIP -Quiet -ErrorAction Stop}
                            catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                                if ($Log) {Write-Logfile "$_.Exception.Message"}
                                }
                            }
                        if (!$ping) {
                            if ($ServiceProfileIP -ne "0.0.0.0"){
                                $serversummary += "$($serviceprofile.Name) -  interface at address $($ServiceProfileIP) is not pingable;"
                                if ($Log) {Write-Logfile "$($serviceprofile.Name) -  interface at address $($ServiceProfileIP) is not pingable"}
                                $PingOK = $false
                                }
                            else {
                                $serversummary += "$($serviceprofile.Name) -  cannot find IP for management interface;"
                                if ($Log) {Write-Logfile "$($serviceprofile.Name) -  cannot find IP for management interface;"}
                               $PingOK = $false
                                }      
                             }
                        else{
                            if ($Log) {Write-Logfile "$($serviceprofile.Name) -  interface at address $($ServiceProfileIP) is pingable"}
                            }
            
            
                        if ($MachineIP -ne $null){
                            if ($Log) {Write-Logfile "Ping check for Service Profile IP"}
                            $ping = $null
                            try {$ping = Test-Connection $MachineIP -Quiet -ErrorAction Stop}
                            catch {Write-Host -ForegroundColor $warn $_.Exception.Message
                                if ($Log) {Write-Logfile "$_.Exception.Message"}
                                }
                            }
                        if (!$ping) {
                            if ($ServiceProfileIP -ne "0.0.0.0"){
                                $serversummary += "$($serviceprofile.PnDn) -  interface at address $($MachineIP) is not pingable;"
                                if ($Log) {Write-Logfile "$($serviceprofile.PnDn) -  interface at address $($MachineIP) is not pingable"}
                                $PingOK = $false
                                }
                            else {
                                $serversummary += "$($serviceprofile.PnDn) -  cannot find IP for management interface;"
                                if ($Log) {Write-Logfile "$($serviceprofile.PnDn) -  cannot find IP for management interface;"}
                                $PingOK = $false
                                }      
                             }
                        else{
                            if ($Log) {Write-Logfile "$($serviceprofile.PnDn) -  interface at address $($MachineIP) is pingable"}
                            }
                        }

                   }
                else {
                    if ($UCSserver.OperState -match "inaccessible"){
                        $PingOK = $false
                        $serversummary += " $($serverIdentity) -  no management interface IP address available - server inaccessible;"
                        }
                    }
                if (!$PingOK){
                            Write-Host -ForegroundColor $fail "Fail";$serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                
                            }
                        else{
                            Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                            }

                $report = $report + $serverObj
                }
        
           
            else{
                Write-Host "Ignoring $($UCSServerID)" -ForegroundColor Blue
                
                Write-Host "$($UCSServerID) in $($IgnoreServerIds)" -ForegroundColor Blue 
        
                }
            }
        Disconnect-Ucs
        }
    else{
        if ($Log) {Write-Logfile "Cannot connect to $($UCSMServer)"}
        $serversummary += "Cannot connect to $($UCSMServer)"
        }
    }         

### Begin report generation
if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    if ($IgnoreServerIDs){
        $ignoretext = "Configured to ignore servers: $($IgnoreServerIDs)."
        }
    if ($IgnoreObjects){
        $ignoretext += "Configured to ignore objects: $($IgnoreObjects)."
        }
    #Create HTML Report
   
    
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        Out-File -FilePath "$($OutputFolder)\UCS_Error_Status_Fail.txt"
        
        #Generate the HTML
        $coloredheader = "<h1 align=""center""><a href=$ReportURL  class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>UCS Health Details</h3>
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
        $serversummaryhtml = "<h3>UCS Health Details</h3>
                        <p>$ignoretext</p>
                        <p>No UCS health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>UCS GreenScreen - $servicestatus</title>
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
        
    #UCS Health Report Table Header
    $htmltableheader = "<h3>UCS Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>UCS System</th>
                        <th>Service Profile</th>
                        <th>Blade/Server</th>
                        <th>Ping</th>
                        <th>System</th>
                        <th>Uptime (hrs)</th>
                        <th>Faults</th>
                        <th>Networks</th>
                        <th>Hardware</th>
                        </tr>"

    #UCS Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader                    
    $report = $report | sort -property "Service Profile"                 
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        if ($line -match "Fail" -or $line -match "Warn" -or $line."uptime (hrs)" -lt $MinimumUptime ){
            write-host "$($line."Service Profile") ($($line."Blade/Server")) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line."Service Profile") ($($line."Blade/Server")) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }

    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.UCSSystem)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "Service Profile")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Blade/Server")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
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
        $htmltablerow += (New-ServerHealthHTMLTableCell "Faults")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
        
        }
    
     #Add passes after so they show up last
    foreach ($reportline in $passreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.UCSSystem)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "Service Profile")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Blade/Server")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Ping")
        $htmltablerow += (New-ServerHealthHTMLTableCell "System")
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
        $htmltablerow += (New-ServerHealthHTMLTableCell "Faults")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
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
            #$servicestatus
            if ($servicestatus -eq "FAIL"){
                #write-host $servicestatus - $reportemailsubject - $now
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

