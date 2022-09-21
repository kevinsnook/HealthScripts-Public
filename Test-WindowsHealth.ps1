<#
.SYNOPSIS
Test-WindowsHealth.ps1 - Windows Health Check Script.

.DESCRIPTION 
Performs a series of health checks on WIndows standalone servers and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.EXAMPLE
.\Test-WindowsHealth.ps1 -Configfile C:\Source\Scripts\windows\Test-WindowsHealth-cfg.ps1
Checks all servers in the organization and outputs the results to the shell window.


.LINK

github/kevinsnook

.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on Windows servers and reports them on a Pass/Fail basis.
If the SendEMail parameter is selected an email is sent showing an overall status i.e. if ANY check has FAILed or everything has PASSed.
Check out the VARIABLES section in the config file to make changes to thresholds/recipients etc
#>

#requires -version 2

[CmdletBinding()]
param (
        [Parameter( Mandatory=$true)]
        [string]$ConfigFile
        
        
    )

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
    param( [string]$logentry )
    $timestamp = Get-Date -DisplayHint Time
    "$timestamp $logentry" | Out-File $logfile -Append
}

function Convert-UTCtoLocal([parameter(Mandatory=$true)][String]$UTCTime)

{
  #($tz set in initializing section)
  if ($Log) {Write-Logfile "Converting $($UTCTime) to timezone $($tz.StandardName)"}
  try {
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($tz.StandardName);
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ);
    
    if ($Log) {Write-Logfile "Resultant time is $($Localtime)"};
    return $LocalTime;
    }
  
  catch {
    return $null;
    }

}

Function Get_IPMI_Info ($ServerHostName)
{

#Get the IPMI (ILO/DRAC) information from within a WIndows machine
# Get the Class instance
$oIPMI=Get-WmiObject -Namespace root\WMI -Class MICROSOFT_IPMI -ComputerName $ServerHostName
# Some constants
[byte]$BMCResponderAddress = 0x20
[byte]$GetLANInfoCmd = 0x02
[byte]$GetChannelInfoCmd = 0x42
[byte]$SetSystemInfoCmd = 0x58
[byte]$GetSystemInfoCmd = 0x59
[byte]$DefaultLUN = 0x00
[byte]$IPMBProtocolType = 0x01
[byte]$8023LANMediumType = 0x04
[byte]$MaxChannel = 0x0b
[byte]$EncodingAscii = 0x00
[byte]$MaxSysInfoDataSize = 19

[byte[]]$RequestData=@(0)
$oMethodParameter=$oIPMI.GetMethodParameters("RequestResponse")
$oMethodParameter.Command=$GetChannelInfoCmd
$oMethodParameter.Lun=$DefaultLUN
$oMethodParameter.NetworkFunction=0x06
$oMethodParameter.RequestData=$RequestData
$oMethodParameter.RequestDataSize=$RequestData.length
$oMethodParameter.ResponderAddress=$BMCResponderAddress
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa392344%28v=vs.85%29.aspx
$RequestData=@(0)
[Int16]$iLanChannel=0
[bool]$bFoundLAN=$false
for(;$iLanChannel -le $MaxChannel;$iLanChannel++){
    $RequestData=@($iLanChannel)
    $oMethodParameter.RequestData=$RequestData
    $oMethodParameter.RequestDataSize=$RequestData.length
    $oRet=$oIPMI.PSBase.InvokeMethod("RequestResponse",$oMethodParameter,(New-Object System.Management.InvokeMethodOptions))
    if($oRet.ResponseData[2] -eq $8023LANMediumType){
        $bFoundLAN=$true
        break;
    }
}

$oMethodParameter.Command=$GetLANInfoCmd
$oMethodParameter.NetworkFunction=0x0c
if($bFoundLAN){
    $RequestData=@($iLanChannel,3,0,0)
    $oMethodParameter.RequestData=$RequestData
    $oMethodParameter.RequestDataSize=$RequestData.length
    $oRet=$oIPMI.PSBase.InvokeMethod("RequestResponse",$oMethodParameter,(New-Object System.Management.InvokeMethodOptions))
    $IPMIIPAddress = (""+$oRet.ResponseData[2]+"."+$oRet.ResponseData[3]+"."+$oRet.ResponseData[4]+"."+ $oRet.ResponseData[5] )
    $IPMIIPAddress
    $RequestData=@($iLanChannel,6,0,0)
    $oMethodParameter.RequestData=$RequestData
    $oMethodParameter.RequestDataSize=$RequestData.length
    $oRet=$oIPMI.PSBase.InvokeMethod("RequestResponse",$oMethodParameter,(New-Object System.Management.InvokeMethodOptions))
    $RequestData=@($iLanChannel,5,0,0)
    $oMethodParameter.RequestData=$RequestData
    $oMethodParameter.RequestDataSize=$RequestData.length
    $oRet=$oIPMI.PSBase.InvokeMethod("RequestResponse",$oMethodParameter,(New-Object System.Management.InvokeMethodOptions))
    }

}




Function Get_IPMI_Health ($ServerHostList,$ShowNoVMs)
{

foreach ($ServerHost in $ServerHostList){
    #Let's find the ILO
    
    $STATUS = $null
    $ServerHostILOIP = Get_IPMI_Info $ServerHost
    if ($Log) {Write-Logfile "Connecting to $($ServerHostILOIP)"}
    $IPMIConnect=$null
    if ($ServerHostILOIP){
        try{$IPMIConnect=Connect-HPEiLO -IP $ServerHostILOIP -Credential $IPMICredential -DisableCertificateAuthentication}
        catch{Write-Output "$($ServerHostILOIP) Ran into an issue: $($PSItem.ToString())"}
        }
    if ($Log) {Write-Logfile "IPMIconnect is $($IPMIConnect)"}
    if ($IPMIConnect){
    ################################ SERVER INFO CHECKS START ################################
        
        $getServerInfo = Get-HPEiLOServerInfo -Connection $IPMIConnect
        foreach($FanInfo in $getServerInfo.FanInfo){
            if ($FanInfo.State -ne "OK"){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($ServerHost) $($FanInfo.Name) is $($FanInfo.State)"
                if ($Log) {Write-Logfile "$($ERRORTEXT)"}
                }
            }
        foreach($TemperatureInfo in $getServerInfo.TemperatureInfo){
            if (($TemperatureInfo.State -notlike "Absent") -And ($TemperatureInfo.State -notlike "OK")){
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($ServerHost) $($TemperatureInfo.Name) is $($TemperatureInfo.State)"  
                if ($Log) {Write-Logfile "$($ERRORTEXT)"}
                }
            }
        
        if ($getServerInfo.PowerSupplyInfo.PowerSupplySummary.PowerSystemRedundancy -ne "Redundant"){
            #write-host "Power supplies are not redundant" -ForegroundColor Red
            $STATUS="RED"
            $ERRORTEXT += "`n`r$($ServerHost) Power supplies are not redundant" 
            write-host $ERRORTEXT
            if ($Log) {Write-Logfile "$($ERRORTEXT)"}

            }
        ################################ SERVER INFO CHECKS END ################################
        
        ################################ ILO HEALTH CHECKS START ################################
        $HealthReport = Get-HPEiLOHealthSummary -Connection $IPMIConnect
        foreach($HealthLine in $HealthReport|get-member){
            if ($HealthLine.MemberType -eq “Property” -and $HealthLine.Name -notlike “__*” -and $HealthLine.Name -notlike “IP" -and $HealthLine.Name -notlike “Hostname" -and $HealthLine.Name -notlike “AgentlessManagementService" -and $($HealthReport.$($HealthLine.Name))){
                switch -regex ($($HealthReport.$($HealthLine.Name)))
                    {
                    "OK" {if ($Log) {Write-Logfile "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}}
                    "Redundant" {if ($Log) {Write-Logfile "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}}
                    "No" {if ($Log) {Write-Logfile "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}}
                    "Ready" {if ($Log) {Write-Logfile "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))"}}
                    default {write-warning "$($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))";$STATUS="RED";$ERRORTEXT += "`n`r$($ServerHost.HostName) $($HealthLine.Name) is $($HealthReport.$($HealthLine.Name))";if ($Log) {Write-Logfile "$($ERRORTEXT)"}}
                    }
                }
            }
        ################################ ILO HEALTH CHECKS END ################################
        
        
        
        
              
        ################################ ILO IML CHECKS START ################################
        if ($Log) {Write-Logfile "IML Check"}
        $result = Get-HPEiLOIML -Connection $IPMIConnect 
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
                $ERRORTEXT += "`n`r$($ServerHost) The critical IML entry descriptions are: `n$allMessage"
                write-host $ERRORTEXT
                if ($Log) {Write-Logfile "$($ERRORTEXT)"}
                }
        ################################ ILO IML CHECKS END ################################
        
        ################################ ILO EVENT LOG CHECKS START ################################
        if ($Log) {Write-Logfile "Event log check"}
        $result=$null
        $result = Get-HPEiLOEventLog -Connection $IPMIConnect
        foreach($output in $result){
            $sevs = $(foreach ($event in $output.EventLog) {$event.Severity})
            $uniqsev = $($sevs | Sort-Object | Get-Unique)
            $sevcnts = $output.EventLog | group-object -property Severity –noelement
            $message = $(foreach ($event in $output.IMLLog) {if($event.Severity -eq "Critical" -and $(Get-Date($event.Created)) -gt $TimeInPast) {$($event.Created) + $($event.Message)}})
            $uniqmessage = $($message | Sort-Object | Get-Unique)
            if($uniqmessage -ne $null){
                $allMessage = [string]::Join("`n",$uniqmessage)
                $STATUS="RED"
                $ERRORTEXT += "`n`r$($ServerHost) The critical Event entry descriptions are: `n$allMessage"
                write-host $ERRORTEXT
                if ($Log) {Write-Logfile "$($ERRORTEXT)"}
                }
          
            }
        ################################ ILO EVENT LOG CHECKS END ################################
        
        }
        if ($IPMIConnect){
            if ($Log) {Write-Logfile "Disconnecting IPMI"}
            Disconnect-HPEiLO -Connection $IPMIConnect
            }
        }
    else{
        write-host "Could not connect to $($ServerHostILOIP)" -ForegroundColor red 
        $STATUS="RED"
        if ($ServerHostILOIP){
            $ERRORTEXT += "`n`r$($ServerHost) Could not connect to $($ServerHostILOIP)"
            }
        else {
            $ERRORTEXT += "`n`r$($ServerHost) Could not fetch IP for ILO"
            }
        if ($Log) {Write-Logfile "$($ERRORTEXT)"}
        write-host $ERRORTEXT
        }
    
    if ($STATUS -ne $null){
        write-host "$($ServerHost) has status $($STATUS)" -ForegroundColor red
        if ($Log) {Write-Logfile "$($ServerHost) has status $($STATUS)"} 
        }
    
    }

return $ERRORTEXT
}

Function Get_WebPage_Details($IPAddress){


$URI = "https://$IPAddress"
write-host $URI

# First retrieve the website
$result = Invoke-WebRequest -Uri $URI

$resultTable = @{}

# Get the title
$resultTable.title = $result.ParsedHtml.title

# Get the HTML Tag
$HtmlTag = $result.ParsedHtml.childNodes | Where-Object {$_.nodename -eq 'HTML'} 

# Get the HEAD Tag
$HeadTag = $HtmlTag.childNodes | Where-Object {$_.nodename -eq 'HEAD'}

# Get the Meta Tags
$MetaTags = $HeadTag.childNodes| Where-Object {$_.nodename -eq 'META'}

# You can view these using $metaTags | select outerhtml | fl 
# Get the value on content from the meta tag having the attribute with the name keywords
$resultTable.keywords = $metaTags  | Where-Object {$_.name -eq 'keywords'} | Select-Object -ExpandProperty content

# Do the same for description
$resultTable.description = $metaTags  | Where-Object {$_.name -eq 'description'} | Select-Object -ExpandProperty content

# Return the table we have built as an object
Write-Output New-Object -TypeName PSCustomObject -Property $resultTable

}

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
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
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ignorelistfile = "$myDir\ignorelist.txt"

$ERRORS=$null
$OutputFolder = [System.IO.Path]::GetDirectoryName($ReportFile)


#...................................
# Email Settings
#...................................


$smtpsettings = @{
    From = $fromaddress
    SmtpServer = $smtpserver
    }

#Times on hosts are held in local time so let's work out current offset to GMT from host running this software
$tz = Get-CimInstance win32_timezone
$GMTOffsetMinutes = ($tz.Bias + $tz.DaylightBias)
$servicestatus = "Pass"

#...................................
# Initialize
#...................................


#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " Windows Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


foreach ($target in $targets){
    write-host "Processing $($target)" -foregroundcolor Yellow
    if ($Log) {Write-Logfile "Processing $($target)"}
    #Custom object properties
    $serverObj = New-Object PSObject
    $serverObj | Add-Member NoteProperty -Name "Server" -Value $target
         
    #Null and n/a the rest, will be populated as script progresses
    $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Services" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Events" -Value $null
    $serverObj | Add-Member NoteProperty -Name "Networks" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Performance" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "n/a"
    $serverObj | Add-Member NoteProperty -Name "Certificates" -Value "n/a"
    #DNS Check
    Write-Host "DNS Check: " -NoNewline;
    if ($Log) {Write-Logfile "DNS Check: "}
    try {$ip = @([System.Net.Dns]::GetHostByName($target).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
    catch {
        Write-Host -ForegroundColor $_.Exception.Message
        if ($Log) {Write-Logfile $_.Exception.Message}
        $ip = $null
        }
    if ( $ip -ne $null ){
        Write-Host -ForegroundColor $pass "Pass"
        if ($Log) {Write-Logfile "Pass"}
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force
        #Is server online
        Write-Host "Ping Check: " -NoNewline; 
        if ($Log) {Write-Logfile "Ping Check: "}
        $ping = $null
        try {$ping = Test-Connection $target -Quiet -ErrorAction Stop}
        catch {Write-Host -ForegroundColor $warn $_.Exception.Message}

        switch ($ping)
        {
            $true {
                Write-Host -ForegroundColor $pass "Pass"
                if ($Log) {Write-Logfile "Pass"}
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
                }
            default {
                Write-Host -ForegroundColor $fail "Fail"
                if ($Log) {Write-Logfile "Fail"}
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                $serversummary += "$($target) - Ping Failed"
                }
            }
        }
    
    #Get Last Bootup Time
    Write-Host "Uptime Check: " -NoNewline;
    $osprops = get-wmiobject -class win32_operatingsystem -ComputerName $target
    $lastboot = $osprops.ConvertToDateTime($osprops.LastBootUpTime)
    $BootUTCTime = $lastboot.touniversaltime()
    if ($Log) {Write-Logfile "OS Properties are $($osprops)"}
    if ($Log) {Write-Logfile "Last boot was $($lastboot)"}
    if ($Log) {Write-Logfile "Last boot UTC was $($BootUTCTime)"}
    if ($Log) {Write-Logfile "Date/time now is $(Get-Date -Format U)"}
    $uptimehours = [math]::round((New-TimeSpan -Start $BootUTCTime -End (Get-Date -Format U)).TotalHours,0) #| Select-Object -ExpandProperty Days
    if ($Log) {Write-Logfile "up for $($uptimehours)"}
    if ($Log) {Write-Logfile "Minimum uptime is $($MinimumUptime)"}
    [int]$uptime = "{0:00}" -f $timespan.TotalHours
    if ($uptimehours -lt $MinimumUptime){
        Write-Host -ForegroundColor $warn "Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
        $serversummary += "$($target) - Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
        }
    else{
        Write-Host -ForegroundColor $pass "Uptime is more than $($MinimumUptime) hours ($($uptimehours))"
        }
    $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 

    #Services Check
    $ServicesOK=$true
    write-host "Services: " -NoNewline
    if ($Log) {Write-Logfile "Services:"}
    $html += '<u>Service Report - Desired Services with State not currently "Running" </u><p>'
    if ($Log) {Write-Logfile "Service Report - Desired Services with State not currently Running"}
    if ($Log) {Write-Logfile "Checking $($DesiredStateServices)"}
    foreach ($DesiredStateService in $DesiredStateServices){
    $DesiredStateServiceStatus = $null
    if ($Log) {Write-Logfile "Processing for service $($DesiredStateService)"}
    try {$DesiredStateServiceStatus = $DesiredStateService | get-service -ComputerName $target -erroraction 'silentlycontinue'}
    catch {
        Write-Output "Bad news" -ForegroundColor $warn 
        Write-Host -ForegroundColor $warn $_.Exception.Message
        if ($Log) {Write-Logfile "$($warn) $($_.Exception.Message)"}
        $serversummary += "$($target) - Exception error discovering state of service $($DesiredStateService)"
        }
    if ($DesiredStateServiceStatus.Status -ne "Running"){
        if ($Log) {Write-Logfile "Cannot find details for $($DesiredStateService) - probably not installed"}
        $serversummary += "$($target) - $($DesiredStateService) not running"
        $html += "Cannot find details for $($DesiredStateService) - probably not installed<p>" 
        $ServicesOK = $false
                  
        }
    else{
        if ($Log) {Write-Logfile "$($DesiredStateService) is running"}
        
        }
    }

    Switch ($ServicesOK) {
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Services" -Value "Fail" -Force}
            $true { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force}
            }

    #Local Disk Health Check
    write-host "Disk space: " -NoNewline
    $DiskSpaceOK=$true
    if ($target -notin $IgnoreServerDiskSpace){
        if ($Log) {Write-Logfile "Disk Space:"}
        if ($Log) {Write-Logfile "Getting logical disk information"}
        $diskreport = invoke-command -computername $target {
        Get-WmiObject Win32_logicaldisk | Select DeviceID, MediaType, VolumeName, `
        @{Name="Size(GB)";Expression={[decimal]("{0:N0}" -f($_.size/1gb))}}, `
        @{Name="Free Space(GB)";Expression={[decimal]("{0:N0}" -f($_.freespace/1gb))}}, `
        @{Name="Free(%)";Expression={"{0,6:P2}" -f(($_.freespace/1gb) / ($_.size/1gb))}} `
        }

        $html += "<u>Logical Disk Report</u><p>"
        $temphtml = $DiskReport | Select DeviceID, VolumeName, "Size(GB)", "Free Space(GB)", "Free(%)" | ConvertTo-HTML -fragment
        $disktable = $DiskReport | Select DeviceID, VolumeName, "Size(GB)", "Free Space(GB)", "Free(%)"
        foreach ($diskline in $disktable){
        if ($diskline."Size(GB)" -gt 0){
            if ($Log) {Write-Logfile "$($diskline)"}
            if ($Log) {Write-Logfile "Disk free on $($diskline.DeviceID) $($diskline.VolumeName) is $($diskline."Free(%)".Trim())"}
            if ($diskline."Free(%)".Trim() -lt $volumePercentFree){
                write-host "Disk free on $($diskline.DeviceID) $($diskline.VolumeName) is below threshold $($volumePercentFree) -  $($diskline."Free(%)".Trim())"
                $serversummary += "$($target) - Disk free on $($diskline.DeviceID) $($diskline.VolumeName) is below threshold $($volumePercentFree)% -  $($diskline."Free(%)".Trim())"
                $DiskSpaceOK = $false
                }
            }
        }
        
        foreach ($line in $temphtml){$html += "$line";}

        $html += "<p>*******************************************************************************************<p>"
        }
    else{
        if ($Log) {Write-Logfile "$($target) is in $($IgnoreServerDiskSpace) - not running disk space checks"}
        }
    Switch ($DiskSpaceOK) {
        $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Fail" -Force}
        $true { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Pass" -Force}
        }
    
    write-host "Hardware: " -NoNewline
    $Model=Get-WmiObject -Class win32_computersystem -ComputerName $target
    if ($Log) {Write-Logfile "Server Model is $($Model.model)"}
    $IsPhysical=($Model.model -notmatch 'VMware')
    if ($Log) {Write-Logfile "Is server physical is $($IsPhysical)"}
    $HardwareOK=$true
    $HardwareERRORS = $null
    if ($Log) {Write-Logfile "Hardware:"}
    if ($IsPhysical){
        if ($target -notin $IgnoreHardwareErrors){
            if ($Log) {Write-Logfile "Getting IPMI information"}
            #Check ILO
            
            $oIPMI=Get-WmiObject -Namespace root\WMI -Class MICROSOFT_IPMI -ComputerName $target
            if ($Log) {Write-Logfile "IPMI entry is $($oIPMI)"}
            $HardwareERRORS = $null
            $HardwareERRORS += Get_IPMI_Health $target $False
            }
        
        else{
            if ($Log) {Write-Logfile "$($target) is in $($IgnoreHardwareErrors) - not running hardware checks"}
            }
        }
    else{
            if ($Log) {Write-Logfile "$($target) is not a physical server so not running IPMI checks"}
            }    
    Switch (!$HardwareERRORS) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail $HardwareERRORS; $serversummary += "$($target) - Hardware $($HardwareERRORS)";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
                }

    #Log File
    $error.clear()
    $fulldate = Get-Date
    $textfile = "c:\source\scripts\windows\" + "ServerHealthChecks\" + $FullDate.ToString("yyyyMMddHHmm") + "-" + "$Target" + ".html"
    if ($Log) {Write-Logfile "Reporting to text file $($textfile)"}
    $global:strname = $env:username
    if ($Log) {Write-Logfile "Run by $($global:strname)"}
    if ($Log) {Write-Logfile "Run on $($target)"}
    $html = $null
    $html += "<html>"
    $html += '<font face="courier">'
    $html += "<title>Server Health Check - $Target</title>"
    $html += "<h3>$FullDate</h3>"
    $html += "<h4>Server Health Check Script - Run by $global:strname</h4>"
    $html += "<h4>Target Server: $Target</h4>"
    $html += "<h4>Hostname: $env:computername</h4>"
    $html += "<h4>Last Boot: $lastboot </h4>"
    $html += "<p>"
    $html += "******************************************************************************************* <p>"

    if ($Log) {Write-Logfile "PS Session"}
    $s = New-PSSession -ComputerName $target -Credential $Credential
    if ($Log) {Write-Logfile "PSSession $($s)"}
       

    $html += "<p> ******************************************************************************************* <p>"

    #EventLog Checks
    write-host "Events: " -NoNewline
    if ($Log) {Write-Logfile "Querying Application Log on $($Target)"}
    $EventsOK=$true
    $appeventlog = invoke-command -computername $target {
        $targetDate = Get-Date
        $targetdate = $targetdate.addhours(-$MaxHoursToScanLog)
        get-eventlog -logname "Application" -after $targetdate | where-object {$_.entrytype -ne "Information" -and $_.Source -ne "Print" -and $_.Source -ne "TermServDevices" -and $_.EventID -notin $IgnoreServerEvents} 
        }
    
    

    if ($appeventlog){
        $EventsOK = $false
        $html += "<u>Application Log Non-Information Events (Last $($MaxHoursToScanLog) Hours)</u><p>"
        if ($Log) {Write-Logfile "Application Log Non-Information Events (Last $($MaxHoursToScanLog) Hours)"} 
        $temphtml = $appeventlog |  Select TimeGenerated, EntryType, Source, Message | ConvertTo-HTML -fragment
        foreach ($line in $temphtml){
            $html += "$line"
            if ($Log) {Write-Logfile "$($line)"}
            $serversummary += "$($target) - $($line)"
            }

        }
                  
    ELSE {$html += "No non-informational events found in application log in past $($MaxHoursToScanLog) hours <p>";if ($Log) {Write-Logfile "No non-informational events found in application log in past $($MaxHoursToScanLog) hours"}}

    $html += "<p>*******************************************************************************************<p>"

    if ($Log) {Write-Logfile "Querying System Log on $($Target)"}
    $syseventlog = invoke-command -computername $Target {
        $targetdate = get-date
        $targetdate = $targetdate.addhours(-$MaxHoursToScanLog)
        get-eventlog -logname "System" -after $targetdate | where-object {$_.entrytype -ne "Information" -and $_.source -ne "Print" -and $_.source -ne "TermServDevices" -and $_.EventID -notin $IgnoreServerEvents} 
        }
    
    

    if ($syseventlog){
        $EventsOK = $false
        $html += "<u>System Log Non-Information Events (Last $($MaxHoursToScanLog) Hours)</u><p>"
        $temphtml = $syseventlog | Select TimeGenerated, EntryType, Source, Message | ConvertTo-HTML -fragment
        ForEach ($line in $temphtml){
            $html += "$Line"
            if ($Log) {Write-Logfile "$($line)"}
            $serversummary += "$($target) - $($line)"
            }
        }
                  
    else {$html += "No non-informational events found in system log in past $($MaxHoursToScanLog) hours<p>";if ($Log) {Write-Logfile "No non-informational events found in application log in past $($MaxHoursToScanLog) hours"}}

    $html += "<p>*******************************************************************************************<p>"

    Switch ($EventsOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Events" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Events" -Value "Fail" -Force}
                }

    
    write-host "Networks: " -NoNewline
    if ($Log) {Write-Logfile "Pinging all manual Network Adapters $($Target)"}
    $NetworksOK=$true
    $serverIPaddresses = Get-NetIPAddress -CimSession $target -AddressFamily IPv4 -PrefixOrigin Manual | where {$_.IPAddress -notin $IgnoreIPaddresses}
    foreach ($serverIPAddress in $serverIPaddresses){
        $ping = $null
        try {$ping = Test-Connection $serverIPAddress.IPAddress -Quiet -ErrorAction Stop}
        catch {Write-Host -ForegroundColor $warn $_.Exception.Message}
        switch ($ping){
            $true {if ($Log) {Write-Logfile "$($target) - $($serverIPAddress.IPAddress) - Pass"}
                }
            default {if ($Log) {if ($Log) {Write-Logfile "$($target) $($serverIPAddress.IPAddress) - Fail"}
                $NetworksOK=$false
                $serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
                $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force
                $serversummary += "$($target) - $($serverIPAddress.IPAddress) - Ping Failed"
                }
            }
        }
    }
    if ($Log) {Write-Logfile "Querying Network Adapters $($Target)"}
    $NetAdapters = Get-NetAdapter -CimSession $target | where {$_.Name -notin $IgnoreNetworkFailures}
    foreach ($NetAdapter in $NetAdapters){
        if ($NetAdapter.Status -ne "Up"){
            $NetworksOK=$false
            write-host $NetAdapter.Name
            write-host $NetAdapter.Status
            $serversummary += "$($target) - $($NetAdapter.Name) is $($NetAdapter.Status)"
            }
        
        }
    Switch ($NetworksOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Networks" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Networks" -Value "Fail" -Force}
                }
    
    write-host "Performance: " -NoNewline
    if ($Log) {Write-Logfile "Querying CPU Load $($Target)"}
    $PerformanceOK=$true
    #Check CPU Load
    $cpudata = get-wmiobject win32_processor -computername $target | measure-object -property LoadPercentage -average | select Average
    $html += "<u>CPU Load (Average)</u><p>"
    $cpuusage = $($cpudata.average)
    if ($Log) {Write-Logfile "Maximum CPU Usage allowed = $($CPUUsagePercent)"}
    if ($Log) {Write-Logfile "CPU Usage = $($cpuusage)"}
    if ($cpuusage -ge 80 -and $cpuusage -le 90){$html += '<font color="orange">' + "Average CPU Load: $cpuusage%" + '</font>'}
    elseif ($cpuusage -gt 90){$html += '<font color="red">' + "Average CPU Load: $cpuusage%" + '</font>'}
    elseif ($cpuusage -lt 80){$html += '<font color = "green">' + "Average CPU Load: $cpuusage%" + '</font>'}
    $html += "<p>*******************************************************************************************<p>"
    if ($cpuusage -gt $CPUUsagePercent){
        $PerformanceOK=$false
        if ($Log) {Write-Logfile "CPU Usage ($($cpuusage)%) is greater than maximum allowed ($($CPUUsagePercent)%)"}
        $serversummary += "CPU Usage ($($cpuusage)%) is greater than maximum allowed ($($CPUUsagePercent)%)"
        }

    #Check Memory Usage
    if ($Log) {Write-Logfile "Getting Memory Usage"}
    $html += "<u>Memory Usage Report</u><p>"
    $memdata = get-wmiobject win32_operatingsystem -computername $target | select FreePhysicalMemory, FreeVirtualMemory, TotalVirtualMemorySize, TotalVisibleMemorySize
    $freephysicalmem = $($memdata.freephysicalmemory)
    $freevirtualmem = $($memdata.freevirtualmemory)
    $totalvirtualmem = $($memdata.totalvirtualmemorysize)
    $totalvisiblemem = $($memdata.totalvisiblememorysize)
    $memusage = ($totalvisiblemem - $freephysicalmem) / $totalvisiblemem * 100
    $freemem = $freephysicalmem / $totalvisiblemem * 100
    if ($Log) {Write-Logfile "Free memory is $($freemem)"}
    if ($Log) {Write-Logfile "Minimum free memory allowed = $($MemoryFreeUsagePercent)"}
    [decimal]$freemem = "{0:N0}" -f $freemem

    if ($freemem -lt 10){$html += '<font color="red">' + "Free Memory (%): $freemem" + '</font>'}
    elseif ($freemem -gt 10 -and $freemem -le 20){$html += '<font color="orange">' + "Free Memory (%): $freemem" + '</font>'}
    elseif ($freemem -gt 20){$html += '<font color="green">' + "Free Memory (%): $freemem" + '</font>'}
    $html += "<p>*******************************************************************************************<p>"
    if ($freemem -lt $MemoryFreeUsagePercent){
        $PerformanceOK=$false
        if ($Log) {Write-Logfile "Memory free ($($freemem)%) is less than minimum allowed ($($MemoryFreeUsagePercent)%)"}
        $serversummary += "Memory free ($($freemem)%) is less than minimum allowed ($($MemoryFreeUsagePercent)%)"
        
        }
    
    Switch ($PerformanceOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Performance" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Performance" -Value "Fail" -Force}
                }
    
    write-host "Certificates: " -NoNewline
    if ($Log) {Write-Logfile "Querying Certificates on $($Target)"}
    $CertificatesOK=$true
    
    $servercerts = Invoke-Command -ComputerName $target -Scriptblock{
        $arrCerts = Get-Childitem Cert:\LocalMachine\ -Recurse                   
        $HashArray=@()
        foreach ($objItem in $arrCerts) {
        Try   { $blnFound = ($objItem.HasPrivateKey -eq $True) } 
        Catch { $blnFound = $False }                             
        if ($blnFound) {                                         
            $arrSplit = $objItem.PSParentPath -split "::"
            $Hash = (New-Object PSObject -Property @{
                "Path" = $arrSplit[1]
                "SubjectName" = $objItem.SubjectName.Name
                "Expires" = $objItem.NotAfter.DateTime 
                })

            $HashArray += $Hash
            }
        }
        return $HashArray
    }
    foreach ($servercert in $servercerts){
        $CertExpiring = [math]::round((New-TimeSpan -Start (Get-Date) -End $servercert.Expires).TotalDays,0)
        if ($Log) {Write-Logfile "Certificate $($servercert.SubjectName) installed at path $($servercert.Path) expires in $($CertExpiring) days"}
        if ($CertExpiring -lt $CertificateTimeToAlert){
            if ($Log) {Write-Logfile "Certificate $($servercert.SubjectName) installed at path $($servercert.Path) expiring $($CertExpiring) days is less than threshold $($CertificateTimeToAlert)"}
            $CertificatesOK=$false
            $serversummary += "Certificate $($servercert.SubjectName) installed at path $($servercert.Path) expires in $($CertExpiring) days"
            }
        }
    Switch ($CertificatesOK) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Certificates" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Certificates" -Value "Fail" -Force}
                }

    #Add this servers output to the $report array
    $report = $report + $serverObj
    
    #Export Log File
    $html | out-file $textfile
    Get-PSSession | Remove-PSSession 
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    
}

### Begin report generation



if (Test-Path "$($OutputFolder)\Windows_Error_Status_Fail.txt"){
            del "$($OutputFolder)\Windows_Error_Status_Fail.txt"
            }

if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    
    if ($IgnoreServerEvents){
        $ignoretext = $ignoretext + "Configured to ignore Server Events: $($IgnoreServerEvents)."
        }
    if ($IgnoreServerDiskSpace){
        $ignoretext = $ignoretext + "Configured to not log disk space on: $($IgnoreServerDiskSpace)."
        }
    if ($IgnoreHardwareErrors){
        $ignoretext = $ignoretext + "Configured to ignore hardware errors on: $($IgnoreHardwareErrors)."
        }
    if ($IgnoreNetworkFailures){
        $ignoretext = $ignoretext + "Configured to ignore network failures on: $($IgnoreNetworkFailures)."
        }  

    if ($IgnoreIPaddresses){
        $ignoretext = $ignoretext + "Configured to ignore IP addresses: $($IgnoreIPaddresses)."
        }  
    
    if ($Log) {Write-Logfile "Ignore set is $($ignoretext)"}
    #Create HTML Report
       
                
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        
        Out-File -FilePath "$($OutputFolder)\Windows_Error_Status_Fail.txt"
        #Generate the HTML
        $coloredheader = "<h1 align=""center""><a href=$ReportURL class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>Windows Health Details</h3>
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
        $serversummaryhtml = "<h3>Windows Health Details</h3>
                        <p>$ignoretext</p>
                        <p>No Windows health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>Windows GreenScreen - $servicestatus</title>
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
        
    #Windows Health Report Table Header
    
    $htmltableheader = "<h3>Windows Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Server</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>Services</th>
                        <th>Events</th>
                        <th>Networks</th>
                        <th>Hardware</th>
                        <th>Performance</th>
                        <th>Disk Space</th>
                        <th>Certificates</th>
                        </tr>"

    #Windows Health Report Table
    
    $serverhealthhtmltable = $null
    $serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader                    
                        
    foreach ($line in $report){
        #Pop reportlines into separate arrays based on whether they have errors or not
        if (($line -match "Fail") -or ($line -match "Warn") -or ($line."uptime (hrs)" -lt $MinimumUptime) ){
            write-host "$($line.server) has failures/warnings" -ForegroundColor Red
            $failreport += $line
            }
        else{
            write-host "$($line.server) is OK" -ForegroundColor Green
            $passreport += $line
            }
        }

    #Add failures to top of table so they show up first
    foreach ($reportline in $failreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.server)</td>"
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Events")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Performance")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Certificates")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    
    
        }
    
     #Add passes after so they show up last
    foreach ($reportline in $passreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.server)</td>"
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Events")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Networks")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Performance")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Certificates")
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

Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear();
Write-Host "End"
if ($Log) {Write-Logfile "End"}
Stop-Transcript

