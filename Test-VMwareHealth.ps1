<#
.SYNOPSIS
Test-VMwareHealth.ps1 - VMware Health Check Script.

.DESCRIPTION 
Performs a series of health checks on vCenters and ESXi hosts and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.EXAMPLE
.\Test-VMwareHealth.ps1 -ConfigFile C:\Source\Scripts\VMware\test-VMwarehealth-cfg.ps1
Checks all UCS systems in the organization and outputs the results to the shell window.

.LINK

github\kevinsnook

.NOTES
Written by: Kevin Snook (some portions Paul Cunningham)

.OVERVIEW
The script runs through a number of checks on vCenters and ESXi servers in a VMware estate and reports them on a Pass/Fail basis.
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

Function Check_VMHost_Running_Services
{
param (
    $VMHost
)

$RUNNINGSERVICES = $VMHost| Get-VMHostService | where {($_.Running -eq $True)} 

if ($Log) {Write-Logfile "Version on $($VMHost) is $($VMHost.Version)"}
if ($Log) {Write-Logfile "Running services on $($VMHost) are $($RUNNINGSERVICES)"}
$NORMALSERVICES = @("DCUI","lbtd","vmsyslogd","vpxa")
$VMHostCluster = Get-cluster -VMHost $VMHost
#If this is in a cluster with HA enabled then the FDM service should be running as well
if($VMHostCluster.HAEnabled){
    $NORMALSERVICES += "vmware-fdm"
    }
#If this is a host with NTP enabled then the NTPD service should be running as well    
$NTPStatus = $VMHost | Get-VMHostNtpServer
if ($Log) {Write-Logfile "NTP server is $($NTPStatus)"}
if ($NTPStatus) {
    $cmd = '/etc/init.d/ntpd status'
    $plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
    $remoteCommand = '"' + $cmd + '"'
    $commandoutput = $null
    $commandoutput = run-ssh-command $VMHost $ESXiMonitorCredential.UserName $ESXiMonitorCredential.Password $remoteCommand $false
    if ($commandoutput -contains "ntpd is not running"){
        if ($Log) {Write-Logfile "NTP service not running"}
        $ERRORSERVICES += "ntpd "
        }
    else{
        if ($Log) {Write-Logfile "NTP service running"}
        }
    }
if ($Log) {Write-Logfile "Checking the following services are running: $($NORMALSERVICES)"}
foreach ($NORMALSERVICE in $NORMALSERVICES){
    if ($Log) {Write-Logfile "Is service $($NORMALSERVICE) running"}
    if ($RUNNINGSERVICES -match $NORMALSERVICE){
        if ($Log) {Write-Logfile "$($NORMALSERVICE) in $($RUNNINGSERVICES)"}
        }
    else{
        if ($Log) {Write-Logfile "$($NORMALSERVICE) not in $($RUNNINGSERVICES)"}
        $ERRORSERVICES += "$NORMALSERVICE "
        }
    }
 
return $ERRORSERVICES
}

function Get-vCSA-Services {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "GET"
       
       if (([regex]::match($vCSAVersion,"6.7")).success){
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}

      }
  
       return $listvCSAServices
}


Function Test-WebServerSSL {
# Function original location: http://en-us.sysadmins.lv/Lists/Posts/Post.aspx?List=332991f0-bfed-4143-9eea-f521167d287c&ID=60
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$URL,
        [Parameter(Position = 1)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,
        [Parameter(Position = 2)]
        [Net.WebProxy]$Proxy,
        [Parameter(Position = 3)]
        [int]$Timeout = 15000,
        [switch]$UseUserContext
    )
Add-Type @"
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
namespace PKI {
    namespace Web {
        public class WebSSL {
            public Uri OriginalURi;
            public Uri ReturnedURi;
            public X509Certificate2 Certificate;
            //public X500DistinguishedName Issuer;
            //public X500DistinguishedName Subject;
            public string Issuer;
            public string Subject;
            public string[] SubjectAlternativeNames;
            public bool CertificateIsValid;
            //public X509ChainStatus[] ErrorInformation;
            public string[] ErrorInformation;
            public HttpWebResponse Response;
        }
    }
}
"@
    $ConnectString = "https://$($url):$($port)"
    $WebRequest = [Net.WebRequest]::Create($ConnectString)
    $WebRequest.Proxy = $Proxy
    $WebRequest.Credentials = $null
    $WebRequest.Timeout = $Timeout
    $WebRequest.AllowAutoRedirect = $true
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    try {$Response = $WebRequest.GetResponse()}
    catch {}
    if ($WebRequest.ServicePoint.Certificate -ne $null) {
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
        catch {$SAN = $null}
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
        $Status = $chain.Build($Cert)
        New-Object PKI.Web.WebSSL -Property @{
            OriginalUri = $ConnectString;
            ReturnedUri = $Response.ResponseUri;
            Certificate = $WebRequest.ServicePoint.Certificate;
            Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
            Subject = $WebRequest.ServicePoint.Certificate.Subject;
            SubjectAlternativeNames = $SAN;
            CertificateIsValid = $Status;
            Response = $Response;
            #ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
        }
        $chain.Reset()
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    } else {
        Write-Error $Error[0]
    }
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
    if ($Log) {Write-Logfile $alarm.Entity}
    $alarm.Status = $triggeredalarm.OverallStatus
  	$alarm.Time = $triggeredalarm.Time
    if ($alarm.Status -eq "red"){
        if ($alarm.Entity -notcontains "OmniStackVC" -and $alarm.Alarm[0] -notcontains "Virtual machine memory usage"){
            "`n`r$($alarm.Entity) has a critical alert ($($alarm.Alarm[0])) timed at $($alarm.Time)"
            }
        }
    }
}
Function run-ssh-command{
param (
    
    $ESXiHostList,
    $UserName,
    $EncryptedPassword,
    $Command,
    [boolean]$isvCenter
    
)

$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($EncryptedPassword)
$decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
$sshpreviousstatus=$null
foreach ($ESXiHost in $ESXiHostList){
    if ($Log) {Write-Logfile "starting ssh services on $ESXiHost"}
    if ($isvCenter){
        if ($Log) {Write-Logfile write-host "it's a vcenter"}
        $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
        if ($sshService.State -eq "STOPPED"){
            if ($Log) {Write-Logfile "SSH service stopped on vCenter $($vCenterFQDN) - starting it"}
            $sshpreviousstatus = "Off"
            $startedService = Start-vCSA-Service -ServiceName "sshd" -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion
            $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
            }
        
        if ($Log) {Write-Logfile "Executing Command on $ESXiHost"}
        $output = $plink + " " + "-ssh" + " " + $UserName + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        try {$message = Invoke-Expression -command $output}
        catch {Write-Host -ForegroundColor $warn "Exception message is $($_.Exception.Message)"
            $message = "Error Logging On $($_.Exception.Message)"
            }
        $message
        if ($Log) {Write-Logfile $message}
        
        if ($sshpreviousstatus -eq "Off"){
            if ($Log) {Write-Logfile "SSH service previously stopped on vCenter $($vCenterFQDN) - stopping it"}
            $stoppedService = Stop-vCSA-Service -ServiceName "sshd" -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion
            $sshService = Get-vCSA-Services -AuthTokenValue $FuncAuthToken -vCSAVersion $vcsaVersion | where {$_."Service Name" -eq "sshd"}
            }
        }
    else{
        if ($Log) {Write-Logfile "It's a host"}
        $sshstatus= Get-VMHostService  -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"}
        if ($sshstatus.Running -eq $False) {
            $sshpreviousstatus = "Off"
            Get-VMHostService -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"} | Start-VMHostService 
            }
        if ($Log) {Write-Logfile "Executing Command on $ESXiHost"}
        $output = $plink + " " + "-ssh" + " " + $UserName + "@" + $ESXiHost + " " + "-pw" + " " + $decrypted + " " + $remoteCommand
        try {$message = Invoke-Expression -command $output}
        catch {Write-Host -ForegroundColor $warn "Exception message is $($_.Exception.Message)"
            $message = "Error Logging On $($_.Exception.Message)"
            if ($Log) {Write-Logfile "Error Logging On $($_.Exception.Message)"}
            }
        $message
        if ($sshpreviousstatus -eq "Off"){
            if ($Log) {Write-Logfile "SSH service on $ESXiHost was previously off so stopping service"}
            $tsmsshservice = Get-VMHostService -VMHost $ESXiHost| where {$psitem.key -eq "tsm-ssh"} 
            Stop-VMHostService -HostService $tsmsshservice -Confirm:$false
            }
        }
    
    }
}

#Function to convert the given credentials to Base64 encode
function Set-Credentials {
    param (
       [Parameter(Mandatory=$true)][string]$username,
       [Parameter(Mandatory=$true)][string]$password
    )
    
    $pair = "${username}:${password}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
 
    $basicAuthValue = "Basic $base64"
    return $basicAuthValue
}

#Function to request session id
function Create-Session {

	Ignore-Certificate
	$responsesessionid = Invoke-vCenterTokenRequest -Uri $RestApiUrl/com/vmware/cis/session -method "POST"
	
    return $responsesessionid
}

#Function to create session id
function Invoke-vCenterTokenRequest {
    param (
        [string]$uri=$REST_URL,
        [string]$method,
        [string]$body=$null
    )
    
    $headers = @{
        'authorization' =  $creds;
        'content-type' =  'application/json';
        'Accept' = 'application/json';
        
    }
    $response = Invoke-RestMethod -uri $uri -Headers $headers -Method $method -Body $body 
    
    return $response
}

#Function to ignore vCenter certificate
function Ignore-Certificate {

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

}

#Function to list the Health of vCSA
function Get-Health-Message{
    param (
       [Parameter(Mandatory=$true)][string]$colour
    )
            switch($colour){
                "green" {$message = "Service is healthy"}
                "orange" {$message = "The service health is degraded. The service might have serious problems"}
                "red"  {$message = "The service is unavaiable and is not functioning properly or will stop functioning soon"}
                "yellow" {$message = "The service is healthy state, but experiencing some levels of problems.Database storage health"}
                "gray"  {$message = "No health data is available for this service"}
                "unknown" {$message = "No health data is available for this service"}
                default {$message = "No health data is available for this service"}
            }

    return $message
}

#Function to list vCSA disks and partitions
function Get-vCSA-Disks{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
       
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"       

       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/storage
       $listvCSADisks = $respond.value | Select-Object -Property @{N='Disk Number';E={$_.disk}},@{N='Partition Name';E={$_.partition}},@{N='Description';E={$_.description.default_message}} | Sort-Object -Property 'Disk Number'

       return $listvCSADisks
}


#Function to list the vCSA health status
function Get-Health-Status{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )

       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"       

       $respondOverallHealth = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/system
       $overallHealthMessage = Get-Health-Message -colour $respondOverallHealth.value

       $lastCheck = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/system/lastcheck

       $respondLoad = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/load
       $loadHealthMessage = Get-Health-Message -colour $respondLoad.value

       $respondMemory = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/mem
       $memoryHealthMessage = Get-Health-Message -colour $respondMemory.value

       $respondStorage = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/storage
       $storageHealthMessage = Get-Health-Message -colour $respondStorage.value

       $respondDatabase = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/database-storage
       $databaseHealthMessage = Get-Health-Message -colour $respondDatabase.value

       $respondSwap = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/health/swap
       $swapHealthMessage = Get-Health-Message -colour $respondSwap.value


       $healthStatus = New-Object -TypeName psobject 
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Overall Health' -Value $("$($respondOverallHealth.value) , Health Message: $($overallHealthMessage) , LastCheck: $($lastCheck.value)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'CPU Load' -Value $("$($respondLoad.value) , Health Message: $($loadHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $("$($respondMemory.value) , Health Message: $($memoryHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Storage' -Value $("$($respondStorage.value) , Health Message: $($storageHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Database' -Value $("$($respondDatabase.value) , Health Message: $($databaseHealthMessage)")
       $healthStatus | Add-Member -MemberType NoteProperty -Name 'Swap' -Value $("$($respondSwap.value) , Health Message: $($swapHealthMessage)")
      

       return $healthStatus
}

#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Get-vCSA-Services {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "GET"
       if (([regex]::match($vCSAVersion,"6.7")).success){
       
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/vmon/service
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services
           $listvCSAServices = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAServices
}

#Function to get vCSA version and uptime
function Get-vCSA-Version {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
        
       $method = "GET"
        write-host "starting $($RestApiUrl)"
        if ($Log) {Write-Logfile "starting $($RestApiUrl)"}
       $respondVersion = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/version
       $listvCSAVersion = $respondVersion.value | Select-Object -Property @{N='Product';E={$_.product}},@{N='Summary';E={$_.summary}},@{N='Type';E={$_.type}},@{N='Install Time';E={$_.install_time}},@{N='Build';E={$_.build}},@{N='Version';E={$_.version}},@{N='Release Date';E={$_.releasedate}}
       if ($Log) {Write-Logfile "finished version"}
       $respondUptime = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/system/uptime
       $listvCSAUptime = $respondUptime.value 
       if ($Log) {Write-Logfile "finished uptime"}
       $Timespan = New-Timespan -Seconds $listvCSAUptime 
       $listvCSAVersion | Add-Member -MemberType NoteProperty -Name 'System uptime' -Value $("$($Timespan.Days) Days, $($Timespan.Hours) Hours, $($Timespan.Minutes) Minutes")
        
       return $listvCSAVersion
}

#Function to list the status of the services managed by vmware-vmon(VMware Service Lifecycle Manager) service.
function Get-vMon-Services{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"            
 
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/vmon/service
       $listVmonServices = $respond.value | Select-Object -Property @{N='ServiceName';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Health';E={$_.value.health}},@{N='Startup Type';E={$_.value.startup_type}} | Sort-Object -Property 'State'
       if ($Log) {Write-Logfile "VMON Services Found: $($listVmonServices)"}
       return $listVmonServices
}

#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Stop-vCSA-Service {
    param (
       [Parameter(Mandatory=$true)][string]$ServiceName,
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "POST"
       if ($Log) {Write-Logfile "Stopping service $($ServiceName)"}
       if (([regex]::match($vCSAVersion,"6.7")).success){
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services/$ServiceName/stop
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services/{$ServiceName}/stop
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAService
}


#Function to list the status of all vCSA services. Available only in vCSA 6.7.
function Start-vCSA-Service {
    param (
       [Parameter(Mandatory=$true)][string]$ServiceName,
       [Parameter(Mandatory=$true)][string]$AuthTokenValue,
       [Parameter(Mandatory=$true)][string]$vCSAVersion
    )

       $headers = @{
                        'Accept' = 'application/json';
                        'vmware-api-session-id'= $AuthTokenValue;
                   }
       $method = "POST"
       if ($Log) {Write-Logfile "Stopping service $($ServiceName)"}
       if (([regex]::match($vCSAVersion,"6.7")).success){
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/services/$ServiceName/start
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.key}},@{N='State';E={$_.value.state}},@{N='Description';E={$_.value.description}} | Sort-Object -Property 'State'
      } else{
           $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/appliance/techpreview/services/{$ServiceName}/start
           $listvCSAService = $respond.value | Select-Object -Property @{N='Service Name';E={$_.name}},@{N='Description';E={$_.description}}
      }
  
       return $listvCSAService
}

#Function to report vCenter replication status
function Get-vCSA-Replication-Status{
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
       
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
       $method = "GET"       
       write-host "Running replication status - vcsaversion $($vcsaVersion)"
       #v7.02 onwards = https://{api_host}/api/vcenter/topology/replication-status
       #v6.7 = https://{api_host}/rest/vcenter/topology/replication-status
       if (([regex]::match($vcsaVersion ,"6.7")).success){
          if ($vcsaVersion -eq "6.7.0"){
            if ($Log) {Write-Logfile "Version $($vcsaVersion) Replication Status not supported"}
            }
          else{
            if ($Log) {Write-Logfile "Version $($vcsaVersion) URL https://$($vCenterFQDN)/rest/topology/replication-status"}
            $respond = Invoke-RestMethod -Method $method -Headers $headers -uri https://$vCenterFQDN/rest/topology/replication-status
            $vCenterReplicationStatus = $respond | where {$_.node -eq $vCenterFQDN} | Select-Object node,change_lag,status_available,partner_available,replicating,replication_partner  | Sort-Object -Property node
            if ($Log) {Write-Logfile "Replication status is $($vCenterReplicationStatus)"}
            }
          }
       else{
            if ($Log) {Write-Logfile "Version $($vcsaVersion) URL https://$($vCenterFQDN)/api/vcenter/topology/replication-status"}
            $respond = Invoke-RestMethod -Method $method -Headers $headers -uri https://$vCenterFQDN/api/vcenter/topology/replication-status
            $vCenterReplicationStatus = $respond | where {$_.node -eq $vCenterFQDN} | Select-Object node,change_lag,status_available,partner_available,replicating,replication_partner  | Sort-Object -Property node
            if ($Log) {Write-Logfile "Replication status is $($vCenterReplicationStatus)"}
        }
       
       return $vCenterReplicationStatus
}

Function Get-VCHAConfig {
param (
       [Parameter(Mandatory=$true)]$VCenter
    )

    write-host "Fetching VCHA Status for $($VCenter)"
    $vCenterHAStatus = "Healthy"
    if ($Log) {Write-Logfile "Fetching VCHA Status for $($VCenter)"}
    $vcHAClusterConfig = Get-View failoverClusterConfigurator -Server $VCenter
    foreach ($vcHACluster in $vcHAClusterConfig){
        $vcHAConfig = $vcHACluster.getVchaConfig()
        $vcHAState = $vcHAConfig.State
        switch($vcHAState) {
        configured {
            $activeIp = $vcHAConfig.FailoverNodeInfo1.ClusterIpSettings.Ip.IpAddress
            $passiveIp = $vcHAConfig.FailoverNodeInfo2.ClusterIpSettings.Ip.IpAddress
            $witnessIp = $vcHAConfig.WitnessNodeInfo.IpSettings.Ip.IpAddress

            $vcHAClusterManager = Get-View failoverClusterManager -Server $VCenter
            $vcHAMode = $vcHAClusterManager.getClusterMode()
            $healthInfo = $vcHAClusterManager.GetVchaClusterHealth()
            $vcClusterState = $healthInfo.RuntimeInfo.ClusterState
            $nodeState = $healthInfo.RuntimeInfo.NodeInfo
            
            if ($vcClusterState -notlike "healthy"){
                $vCenterHAStatus = "Unhealthy"
                }
            if ($Log) {Write-Logfile "VCHA Cluster State: $($vcClusterState)"}
            if ($Log) {Write-Logfile "VCHA Node Information:"}
            $nodeinfo = $nodeState | Select NodeIp, NodeRole, NodeState
            foreach ($node in $nodeinfo){
                if ($node.NodeState -notlike "up"){
                    if ($Log) {Write-Logfile "$($node.NodeIp) ($($node.NodeRole)) is not up"}
                    Write-Host -ForegroundColor Red "$($node.NodeIp) ($($node.NodeRole)) is not up"
                    $vCenterHAStatus = "Unhealthy"
                    }
                else{
                    if ($Log) {Write-Logfile "$($node.NodeIp) ($($node.NodeRole)) is up"}
                    Write-Host -ForegroundColor White "$($node.NodeIp) ($($node.NodeRole)) is up"
                    }
                }       
            if ($vcHAMode -notlike "enabled"){
                $vCenterHAStatus = "Disabled"
                }
            ;break
            }
        invalid { Write-Host -ForegroundColor Red "VCHA State is in invalid state ..."
            if ($Log) {Write-Logfile "VCHA config is invalid"}
            Write-Host -ForegroundColor White "VCHA config is invalid"
            $vCenterHAStatus = "Invalid"       
            ;break
            }
        notConfigured { Write-Host "VCHA is not configured"
             if ($Log) {Write-Logfile "VCHA is not configured"}
            Write-Host -ForegroundColor White "VCHA is not configured"
            $vCenterHAStatus = "Healthy"
            ;break}
        prepared { Write-Host "VCHA is being prepared, please try again in a little bit ...";break}
        }
    }

return $vCenterHAStatus
}



#Function to terminate the session 
function Terminate-Session {
    param (
       [Parameter(Mandatory=$true)][string]$AuthTokenValue
    )
    
       $headers = @{
            'Accept' = 'application/json';
            'vmware-api-session-id'= $AuthTokenValue;
       }
            
       $method = "DELETE"
            
       $respond = Invoke-RestMethod -Method $method  -Headers $headers -uri $RestApiUrl/com/vmware/cis/session
       $terminateSession = $respond.value | Select-Object -Property @{N='ESXi Host Name';E={$_.name}},@{N='Connection State';E={$_.connection_state} } ,@{N='Power State';E={$_.power_state} }
   
       return $terminateSession
}

function Find-HBA-State {
     
$views = Get-View -ViewType "HostSystem" -Property Name,Config.StorageDevice 
$result = @()

foreach ($view in $views | Sort-Object -Property Name) {
    if ($Log) {Write-Logfile "Checking $($view.Name)"}
 
    $view.Config.StorageDevice.ScsiTopology.Adapter |where{ $_.Adapter -like "*FibreChannelHba*" } | %{
        $hba = $_.Adapter.Split("-")[2]
 
        $active = 0
        $standby = 0
        $dead = 0
        $inactive = 0
 
        $_.Target | %{ 
            $_.Lun | %{
                $id = $_.ScsiLun
 
                $multipathInfo = $view.Config.StorageDevice.MultipathInfo.Lun | ?{ $_.Lun -eq $id }
 
                $a = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "active*" })
                $s = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "standby" })
                $d = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "dead" })
                $i = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "inactive" })

                $active += $a.Count
                $standby += $s.Count
                $dead += $d.Count
                $inactive += $i.Count
                
            }
        }
        $HBAObj = New-Object PSObject
        $HBAObj | Add-Member NoteProperty -Name "VMHost" -Value $view.Name
        $HBAObj | Add-Member NoteProperty -Name "HBA" -Value $hba
        $HBAObj | Add-Member NoteProperty -Name "Active" -Value $active
        $HBAObj | Add-Member NoteProperty -Name "Dead" -Value $dead
        $HBAObj | Add-Member NoteProperty -Name "Standby" -Value $standby
        $HBAObj | Add-Member NoteProperty -Name "Inactive" -Value $inactive
        


        $csv += "{0},{1},{2},{3},{4},{5}" -f $view.Name, $hba, $active, $dead, $standby, $inactive
        if ($dead -gt 0 -or $inactive -gt 0){
            #Bad paths detected so let's run another rescan to check 
            if ($Log) {Write-Logfile "Bad paths detected (Standby Paths = $($standby) Dead Paths = $($dead) Inactive Paths = $($inactive) ) - HBAs rescanning on $($view.Name)"}
            Get-VMHost -Name $view.Name | Get-VMHostStorage -RescanAllHba
            if ($Log) {Write-Logfile "HBAs rescanned on $($view.Name)"}
            }
        else{
            if ($Log) {Write-Logfile "No bad paths (Standby Paths = $($standby) Dead Paths = $($dead) Inactive Paths = $($inactive) ) - no rescan necessary on $($view.Name)"}
            }
        
        $result += $HBAObj
    }
}

$result

}

function Find-SD-State {
    
$views = Get-View -ViewType "HostSystem" -Property Name,Config.StorageDevice 
$result = @()
 
foreach ($view in $views | Sort-Object -Property Name) {
    if ($Log) {Write-Logfile "Checking $($view.Name)"}
 
    $view.Config.StorageDevice.ScsiTopology.Adapter |where{ $_.Adapter -like "*BlockHba-vmhba32*" } | %{
        $hba = $_.Adapter.Split("-")[2]
 
        $active = 0
        $standby = 0
        $dead = 0
        $inactive = 0
 
        $_.Target | %{ 
            $_.Lun | %{
                $id = $_.ScsiLun
 
                $multipathInfo = $view.Config.StorageDevice.MultipathInfo.Lun | ?{ $_.Lun -eq $id }
 
                $a = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "active*" })
                $s = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "standby" })
                $d = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "dead" })
                $i = [ARRAY]($multipathInfo.Path | ?{ $_.PathState -like "inactive" })

                $active += $a.Count
                $standby += $s.Count
                $dead += $d.Count
                $inactive += $i.Count
            }
        }
        $HBAObj = New-Object PSObject
        $HBAObj | Add-Member NoteProperty -Name "VMHost" -Value $view.Name
        $HBAObj | Add-Member NoteProperty -Name "HBA" -Value $hba
        $HBAObj | Add-Member NoteProperty -Name "Active" -Value $active
        $HBAObj | Add-Member NoteProperty -Name "Dead" -Value $dead
        $HBAObj | Add-Member NoteProperty -Name "Standby" -Value $standby
        $HBAObj | Add-Member NoteProperty -Name "Inactive" -Value $inactive
        


        $csv += "{0},{1},{2},{3},{4},{5}" -f $view.Name, $hba, $active, $dead, $standby, $inactive
        
        $result += $HBAObj
    }
}
$result
}

function get-licensing-key-info {
$licenseArray = @()

foreach ($licenseManager in (Get-View LicenseManager)){
    $vCenterName = ([System.uri]$licenseManager.Client.ServiceUrl).Host
    foreach ($license in $licenseManager.Licenses)
    {
        if ($Log) {Write-Logfile "Checking Licence $($license.Name) Key is $($license.LicenseKey)"}
        $licenseProp = $license.Properties
        $licenseFeatures = $licenseProp | Where-Object {$_.Key -eq 'Feature'}
        if ($Log) {Write-Logfile "Licence features:"}
        foreach ($licenseFeature in $licenseFeatures){
            $feature = $licenseFeature | Select-Object -ExpandProperty Value
            if ($Log) {Write-Logfile "$($feature.Value)"}
            }
           
        $licenseObj = New-Object psobject
        $licenseObj | Add-Member -Name Name -MemberType NoteProperty -Value $license.Name
        $licenseObj | Add-Member -Name LicenseKey -MemberType NoteProperty -Value $license.LicenseKey
        $licenseObj | Add-Member -Name LicenseFeatures -MemberType NoteProperty -Value $licenseFeatures
        $licenseObj | Add-Member -Name vCenter -MemberType NoteProperty -Value $vCenterName
        $licenseArray += $licenseObj
        } 

    }
$licenseArray
}
function Get-ServerHardwareInventoryREDFISH {


param(
    [Parameter(Mandatory=$True)]
    [string]$idrac_ip,
    [Parameter(Mandatory=$False)]
    [string]$idrac_username,
    [Parameter(Mandatory=$False)]
    [string]$idrac_password,
    [Parameter(Mandatory=$False)]
    [string]$x_auth_token,
    [Parameter(Mandatory=$False)]
    [switch]$get_memory,
    [Parameter(Mandatory=$False)]
    [switch]$get_cpu,
    [Parameter(Mandatory=$False)]
    [switch]$get_fans,
    [Parameter(Mandatory=$False)]
    [switch]$get_psu,
    [Parameter(Mandatory=$False)]
    [switch]$get_pcie_devices,
    [Parameter(Mandatory=$False)]
    [switch]$get_pcie_functions,
    [Parameter(Mandatory=$False)]
    [switch]$get_network_devices,
    [Parameter(Mandatory=$False)]
    [switch]$get_system_info
    )

# Function to ignore SSL certs

function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}


# Setting up iDRAC credentials for functions  

function setup_idrac_creds
{

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12

if ($x_auth_token)
{
$global:x_auth_token = $x_auth_token
}
elseif ($idrac_username -and $idrac_password)
{
$user = $idrac_username
$pass= $idrac_password
$secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
$global:credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
}
else
{
$get_creds = Get-Credential
$global:credential = New-Object System.Management.Automation.PSCredential($get_creds.UserName, $get_creds.Password)
}
}

$global:get_powershell_version = $null

function get_powershell_version 
{
$get_host_info = Get-Host
$major_number = $get_host_info.Version.Major
$global:get_powershell_version = $major_number
}

function get_system_info
{

$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"

if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json
$get_result.Oem.Dell.DellSystem
#$get_result
}


function get_fans_powersupplies
{

param(
[Parameter (Mandatory = $true)] [String]$hw_type
)
if ($hw_type -eq "Fans")
{
$uri = "https://$idrac_ip/redfish/v1/Chassis/System.Embedded.1/Thermal"
}
elseif ($hw_type -eq "PowerSupplies")
{
$uri = "https://$idrac_ip/redfish/v1/Chassis/System.Embedded.1/Power"
}

if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json
if ($hw_type -eq "Fans")
{
$get_result.Fans
}
elseif ($hw_type -eq "PowerSupplies")
{
$get_result.PowerSupplies
}
}


function get_memory_cpu_details
{

param(
[Parameter (Mandatory = $true)] [String]$hw_type
)

$expand_query ='?$expand=*($levels=1)'
$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/$hw_type$expand_query"
if ($hw_type -eq "Memory")
{
}
if ($hw_type -eq "Processors")
{
}
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json
$get_result.Members
}

function get_pcie_devices_functions
{
param(
[Parameter (Mandatory = $true)] [String]$hw_type
)
if ($hw_type -eq "PCIeDevices")
{
}
if ($hw_type -eq "PCIeFunctions")
{
}

$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json
foreach ($item in $get_result.$hw_type)
{
$get_uri = "@odata.id"
$pci_uri = $item.$get_uri
$uri = "https://$idrac_ip$pci_uri"
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$hw_result = $result.Content | ConvertFrom-Json
$hw_result
}
}


function get_network_devices
{

$expand_query ='?$expand=*($levels=1)'
$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/NetworkAdapters$expand_query"

if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json

foreach ($item in $get_result.Members)
{
$item
$get_uri = "@odata.id"
$network_port_uri = $item.NetworkPorts.$get_uri
$uri = "https://$idrac_ip$network_port_uri"
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json

foreach ($item in $get_result.Members)
{
$get_uri = "@odata.id"
$network_port_uri = $item.$get_uri
$uri = "https://$idrac_ip$network_port_uri"
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}
$get_result = $result.Content | ConvertFrom-Json
$get_result
}
}
}


# Run code
get_powershell_version
setup_idrac_creds

# Code to check for supported iDRAC version installed

$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"
if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    $RespErr
    return
    }
}


if ($get_memory)
{
get_memory_cpu_details("Memory")
}
if ($get_system_info)
{
get_system_info
}
if ($get_cpu)
{
get_memory_cpu_details("Processors")
}
if ($get_fans)
{
get_fans_powersupplies("Fans")
}
if ($get_psu)
{
get_fans_powersupplies("PowerSupplies")
}
if ($get_pcie_devices)
{
get_pcie_devices_functions("PCIeDevices")
}
if ($get_pcie_functions)
{
get_pcie_devices_functions("PCIeFunctions")
}
if ($get_network_devices)
{
get_network_devices
}

}

Function Get_IDrac_Health($iDRACIP){
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($iDRACCredential.Password)
$decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)


write-host "System Info:" -ForegroundColor Yellow
if ($Log) {Write-Logfile "System Info:"}
try{$system_info = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_system_info}
catch{Write-Host -ForegroundColor Red $_.Exception.Message;$system_info = $null;if ($Log) {Write-Logfile "Error logging on to iDRAC - $($_.Exception.Message)"}}
if ($Log) {Write-Logfile $($system_info)}
if ($system_info -match "TempStatisticsRollupStatus"){
    #write-host "Current status is $($system_info.CurrentRollupStatus)"
    if ($Log) {Write-Logfile "Current status:"}
    write-host "Current status:" -NoNewline
    if ($system_info.CurrentRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    write-host "Battery:" -NoNewline
    if ($system_info.BatteryRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "CPU status:"}
    write-host "CPU:" -NoNewline
    if ($system_info.CPURollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        $CPUDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_cpu
        foreach ($CPUDevice in $CPUDevices){
            write-host "CPU Device ID is $($CPUDevice.Id)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device ID is $($CPUDevice.Id)"}
            write-host "CPU Device State is $($CPUDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device State is $($CPUDevice.Status.State)"}
            write-host "CPU Device HealthRollup is $($CPUDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device HealthRollup is $($CPUDevice.Status.Health)"}
            }
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    write-host "Fan:" -NoNewline
    if ($system_info.FanRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        $FanDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_fans
        foreach ($FanDevice in $FanDevices){
            write-host "Fan Name is $($FanDevice.FanName)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Name is $($FanDevice.FanName)"}
            write-host "Fan Device State is $($FanDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Device State is $($FanDevice.Status.State)"}
            write-host "Fan Device HealthRollup is $($FanDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Device HealthRollup is $($FanDevice.Status.Health)"}
            }
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "IDSDM:"}
    write-host "IDSDM:" -NoNewline
    if ($system_info.IDSDMRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Intrusion:"}
    write-host "Intrusion:" -NoNewline
    if ($system_info.IntrusionRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Licensing:"}
    write-host "Licensing:" -NoNewline
    if ($system_info.LicensingRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Power Supply(s):"}
    write-host "Power Supply(s):" -NoNewline
    if ($system_info.PSRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        $PSUDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_psu
        foreach ($PSUDevice in $PSUDevices){
            write-host "PSU Name is $($PSUDevice.Name)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU Name is $($PSUDevice.Name)"}
            write-host "PSU State is $($PSUDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU State is $($PSUDevice.Status.State)"}
            write-host "PSU  Health is $($PSUDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU  Health is $($PSUDevice.Status.Health)"}
            }
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "SD Card:"}
    write-host "SD Card:" -NoNewline
    if ($system_info.SDCardRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "SEL Log:"}
    write-host "SEL Log:" -NoNewline
    if ($system_info.SELRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Storage:"}
    write-host "Storage:" -NoNewline
    if ($system_info.StorageRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Memory:"}
    write-host "Memory:" -NoNewline
    if ($system_info.SysMemPrimaryStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        $MemoryDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_memory
        foreach ($MemoryDevice in $MemoryDevices){
            write-host "Memory Device Name is $($MemoryDevice.Name)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory Device Name is $($MemoryDevice.Name)"}
            write-host "Memory State is $($MemoryDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory State is $($MemoryDevice.Status.State)"}
            write-host "Memory Health is $($MemoryDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory Health is $($MemoryDevice.Status.Health)"}
            }
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Temperature:"}
    write-host "Temperature:" -NoNewline
    if ($system_info.TempRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    if ($Log) {Write-Logfile "Volt:"}
    write-host "Volt:" -NoNewline
    if ($system_info.VoltRollupStatus -notmatch "OK"){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        }
    else{
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        }

    }
else{
    #If not system_info returned must be an older version of iDRAC - use functions directly 
    if ($Log) {Write-Logfile "iDRAC may be older version - ensure you have the lastest version. Alternatively, the credentials provided for iDRAC connection may not be correct. Proceeding with cutdown monitoring"}
    if ($Log) {Write-Logfile "CPU:"}
    write-host "CPU:" -NoNewline
    $CPUDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_cpu | where {$_.Status.Health -ne "OK" -and $_.Status.State -eq "Enabled"}
    if ($CPUDevices){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        foreach ($CPUDevice in $CPUDevices){
            write-host "CPU Device ID is $($CPUDevice.Id)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device ID is $($CPUDevice.Id)"}
            write-host "CPU Device State is $($CPUDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device State is $($CPUDevice.Status.State)"}
            write-host "CPU Device HealthRollup is $($CPUDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "CPU Device HealthRollup is $($CPUDevice.Status.Health)"}
            }
        } 
    else {
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        } 
    
    if ($Log) {Write-Logfile "Fans:"}
    write-host "Fans:" -NoNewline
    $FanDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_fans | where {$_.Status.Health -ne "OK" -and $_.Status.State -eq "Enabled"}
    if ($FanDevices){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        foreach ($FanDevice in $FanDevices){
            write-host "Fan Name is $($FanDevice.FanName)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Name is $($FanDevice.FanName)"}
            write-host "Fan Device State is $($FanDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Device State is $($FanDevice.Status.State)"}
            write-host "Fan Device HealthRollup is $($FanDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Fan Device HealthRollup is $($FanDevice.Status.Health)"}
            }
        } 
    else {
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        } 

    if ($Log) {Write-Logfile "Power Supplies:"}
    write-host "Power Supplies:" -NoNewline
    $PSUDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_psu | where {$_.Status.Health -ne "OK" -and $_.Status.State -eq "Enabled"}
    if ($PSUDevices){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        foreach ($PSUDevice in $PSUDevices){
            write-host "PSU Name is $($PSUDevice.Name)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU Name is $($PSUDevice.Name)"}
            write-host "PSU State is $($PSUDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU State is $($PSUDevice.Status.State)"}
            write-host "PSU  Health is $($PSUDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "PSU  Health is $($PSUDevice.Status.Health)"}
            }
        } 
    else {
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        } 
    
    if ($Log) {Write-Logfile "Memory:"}
    write-host "Memory:" -NoNewline
    $MemoryDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_memory |where {$_.Status.Health -ne "OK" -and $_.Status.State -eq "Enabled"}
    if ($MemoryDevices){
        write-host "Fail" -ForegroundColor Red
        if ($Log) {Write-Logfile "Fail"}
        foreach ($MemoryDevice in $MemoryDevices){
            write-host "Memory Device Name is $($MemoryDevice.Name)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory Device Name is $($MemoryDevice.Name)"}
            write-host "Memory State is $($MemoryDevice.Status.State)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory State is $($MemoryDevice.Status.State)"}
            write-host "Memory  Health is $($MemoryDevice.Status.Health)" -ForegroundColor Red
            if ($Log) {Write-Logfile "Memory Health is $($MemoryDevice.Status.Health)"}
            }
        }
    else {
        write-host "Pass" -ForegroundColor Green
        if ($Log) {Write-Logfile "Pass"}
        } 
   }

if ($Log) {Write-Logfile "PCIe:"}
write-host "PCIe:" -ForegroundColor Yellow -NoNewline
$PCIEDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_pcie_devices | where {$_.Status.HealthRollUp -ne "OK" -and $_.Status.State -eq "Enabled"}
#$PCIEDevices
#exit
if ($PCIEDevices){
    write-host "Fail" -ForegroundColor Red
    if ($Log) {Write-Logfile "Fail"}
    foreach ($PCIEDevice in $PCIEDevices){
        write-host "PCI Device is $($PCIEDevice.Description)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "PCI Device is $($PCIEDevice.Description)"}
        write-host "PCI Device State is $($PCIEDevice.Status.State)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "PCI Device State is $($PCIEDevice.Status.State))"}
        write-host "PCI Device HealthRollup is $($PCIEDevice.Status.HealthRollup)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "PCI Device HealthRollup is $($PCIEDevice.Status.HealthRollup)"}
        }
    }
else {
    write-host "Pass" -ForegroundColor Green
    if ($Log) {Write-Logfile "Pass"}
    }
#exit
if ($Log) {Write-Logfile "Network:"}
write-host "Network:" -ForegroundColor Yellow -NoNewline
$NetworkDevices = Get-ServerHardwareInventoryREDFISH -idrac_ip $iDRACIP -idrac_username $iDRACCredential.UserName -idrac_password $decrypted -get_network_devices | where {$_.Status.HealthRollUp -ne "OK" -and $_.Status.State -eq "Enabled"}
#$NetworkDevices
if ($NetworkDevices){
    write-host "Fail" -ForegroundColor Red
    if ($Log) {Write-Logfile "Fail"}
    foreach ($NetworkDevice in $NetworkDevices){
        write-host "Network Device ID is $($NetworkDevice.Id)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "Network Device ID is $($NetworkDevice.Id)"}
        write-host "Network Device State is $($NetworkDevice.Status.State)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "Network Device State is $($NetworkDevice.Status.State)"}
        write-host "Network Device HealthRollup is $($NetworkDevice.Status.HealthRollup)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "Network Device HealthRollup is $($NetworkDevice.Status.HealthRollup)"}
        write-host "Network Device Link status is $($NetworkDevice.LinkStatus)"  -ForegroundColor Red
        if ($Log) {Write-Logfile "Network Device Link status is $($NetworkDevice.LinkStatus)"}
        }
    }
else {
    write-host "Pass" -ForegroundColor Green
    if ($Log) {Write-Logfile "Pass"}
    }
}

Function Get_ILO_Health ($HostList,$ShowNoVMs)
{

foreach ($OVCHost in $HostList){
    $STATUS = $null
    $OVCHostILOIP = $OVCHost
    $ILOConnect=$null
    if ($OVCHostILOIP){
        try{$ILOConnect=Connect-HPEiLO -IP $OVCHostILOIP -Credential $ILOCredential -DisableCertificateAuthentication}
        catch{Write-Output "$(OVCHostILOIP) Ran into an issue: $($PSItem.ToString())"}
        }
    if ($ILOConnect){
    ################################ SERVER INFO CHECKS START ################################
        
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
        write-host "Could not connect to $($OVCHostILO)" -ForegroundColor red 
        $STATUS="RED"
        $ERRORTEXT += "`n`r$($OVCHost) Could not connect to $($OVCHostILO)"
        }
    
    if ($STATUS -ne $null){
        write-host "$($OVCHost) has status $($STATUS)" -ForegroundColor red 
        }
    
    }

return $ERRORTEXT
}


function get-licensing-host-info {
$HostlicenseArray = @()


foreach($vc in $global:DefaultVIServers){

    $licMgr = Get-View LicenseManager -Server $vc
    $licAssignmentMgr = Get-View -Id $licMgr.LicenseAssignmentManager -Server $vc
    $AssignedLicenses = $licAssignmentMgr.QueryAssignedLicenses($vc.InstanceUid) | sort EntityDisplayName
    foreach ($AssignedLicense in $AssignedLicenses){
            if ($AssignedLicense.AssignedLIcense.LicenseKey){
            if ($Log) {Write-Logfile "Licence for $($AssignedLicense.EntityDisplayName)"}
            if ($Log) {Write-Logfile "Licence Key is $($AssignedLicense.AssignedLicense.LicenseKey)"}
            if ($Log) {Write-Logfile "Licence Name is $($AssignedLicense.AssignedLicense.Name)"}
            $ExpiryDate = $AssignedLicense.AssignedLicense.Properties.where{$_.Key -eq 'expirationDate'}.Value
            
            if (!$ExpiryDate){
                $ExpiryDate = "Never"
                }
            if ($Log) {Write-Logfile "Expiry Date is $($ExpiryDate)"}
            $HostlicenseObj = New-Object psobject
            $HostlicenseObj | Add-Member -Name Host -MemberType NoteProperty -Value $AssignedLicense.EntityDisplayName
            $HostlicenseObj | Add-Member -Name vCenter -MemberType NoteProperty -Value $vc
            $HostlicenseObj | Add-Member -Name LicenseKey -MemberType NoteProperty -Value $AssignedLicense.AssignedLicense.LicenseKey
            $HostlicenseObj | Add-Member -Name LicenseName -MemberType NoteProperty -Value $AssignedLicense.AssignedLicense.Name
            $HostlicenseObj | Add-Member -Name LicenseExpiryDate -MemberType NoteProperty -Value $ExpiryDate
            $HostlicenseArray += $HostlicenseObj
            }
        }   
    }

$HostlicenseArray
}

function get-VCenter-PSC {

$cmd = '/usr/lib/vmware-vmafd/bin/vmafd-cli get-ls-location --server-name localhost'
$plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
$remoteCommand = '"' + $cmd + '"'
$commandoutput = run-ssh-command $vCenterFQDN $VCRootCredential.UserName $VCRootCredential.Password $remoteCommand $true
if ($Log) {Write-Logfile "Searched for PSC name"}
if ($Log) {Write-Logfile "Command Returned $($commandoutput)"}
$ReturnPSC = ($commandoutput.split("/")[2])
if ($Log) {Write-Logfile "Returning $($ReturnPSC)"}
$ReturnPSC


}

# pass a UTCTime source and it will convert to the locale (UTC+Locale Windows Timezone)

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


#...................................
# Initialize
#...................................


#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
    $timestamp = Get-Date -DisplayHint Time
    "$($timestamp) =====================================" | Out-File $logfile
    Write-Logfile " VMware Server Health Check"
    Write-Logfile "  $now"
    Write-Logfile "====================================="
}

Write-Host "Initializing..."
if ($Log) {Write-Logfile "Initializing..."}


#...................................
# vCenter connection
$VCConnection = Connect-VIServer $VCServer -Credential $VCCredential -AllLinked
if ($VCConnection){
$VCServerList = $global:DefaultVIServers
#Get all licensing info
$VCLicenseArray = get-licensing-key-info
$HostAssignedLicenseArray = get-licensing-host-info
#Get all cluster information
$VCClusters = get-cluster | select-object Name,HAEnabled,HAAdmissionControlEnabled,DRSEnabled,@{N="NumberofHosts";E={($_ | Get-VMHost).Count}}
if ($Log) {Write-Logfile "Processing Clusters"}
#Get all datacenter information
$VCDatacenters = get-datacenter | select-object Name,@{N="NumberofHosts";E={($_ | Get-VMHost).Count}}
if ($Log) {Write-Logfile "Processing Datacenters"}
#Get all HBA states
$HBApathstates = Find-HBA-State
if ($Log) {Write-Logfile "Processing HBAs"}
foreach ($HBApathstate in $HBApathstates){
    if ($Log) {Write-Logfile "$($HBApathstate.VMHost),$($HBApathstate.HBA),$($HBApathstate.Active),$($HBApathstate.Dead),$($HBApathstate.Standby),$($HBApathstate.Inactive)"}
    }
#Get all SD card states
$SDstates = Find-SD-State
if ($Log) {Write-Logfile "Processing SD card adapters"}
foreach ($SDstate in $SDstates){
    if ($Log) {Write-Logfile "$($SDstate.VMHost),$($SDstate.HBA),$($SDstate.Active),$($SDstate.Dead),$($SDstate.Standby),$($SDstate.Inactive)"}
    }
#...................................

#Grab ESXi Hosts
$VMHosts = Get-VMHost | sort-object -Property Name
#...................................

#Find all VCs on this connection
$VCStatus = @{}
foreach ($VCServer in $VCConnection){
    
    $VCStatusOK = $true
    $VCStatus.Add($VCServer.Name,"Pass")
    write-host "Processing vCenter $($VCServer)"
    if ($Log) {Write-Logfile "Processing vCenter $($VCServer)"}
    $vCenterFQDN = $VCServer.Name
    #Main Program
    DO{
        if ($Log) {Write-Logfile "vCenter Server:"}
        Ignore-Certificate
        $response = try { 
                            if ($Log) {Write-Logfile "Invoking $($vCenterFQDN)"}
                            Invoke-WebRequest $vCenterFQDN
                            $RestApiUrl ='https://'+$vCenterFQDN+'/rest'
                            write-host "RestURL is $($RestApiUrl)"
                        } catch { 
                            $_.Exception.Response; 
                            Write-Host "FQDN is not correct or vCenter IP is not reachable. Please check and try again." -ForegroundColor Red 
                            if ($Log) {Write-Logfile "FQDN is not correct or vCenter IP is not reachable. Please check and try again."}
                        }
   
        }While ($response.StatusCode -ne '200')


    DO{
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VCCredential.Password))
        $creds = Set-Credentials -username $VCCredential.UserName -password $password
        $correctToken = 1

        try{
            $AuthenticationToken = Create-Session
            if ($Log) {Write-Logfile "Creating session"}
            if ($AuthenticationToken.Value){
                Start-Sleep -Seconds 2
                $correctToken = 0
                $FuncAuthToken = $AuthenticationToken.Value
            }
        
        }
        catch{
            Write-Host "Wrong Username or Password" -ForegroundColor Red
            if ($Log) {Write-Logfile "Wrong Username or Password"}
            Start-Sleep -Seconds 2
        }

        }While ($correctToken -eq 1)  

    
    #Get the vCSA version 
    if ($Log) {Write-Logfile "VCSA Version"}
    $vcsaVersion = $VCServer.Version
    if ($Log) {Write-Logfile $vcsaVersion}
    #Find any non-running services
    if ($Log) {Write-Logfile "non-running services"}
    $NonRunningVMONServices = Get-vMon-Services -AuthTokenValue $FuncAuthToken | where {$_.State -ne "STARTED" -and $_.'Startup Type' -ne "MANUAL" -and $_.'Startup Type' -ne "DISABLED"} | Select "ServiceName"
    if ($NonRunningVMONServices){
        foreach ($NonRunningVMONService in $NonRunningVMONServices){
            if ($NonRunningVMONService.ServiceName -notin $IgnoreVCServices){
                $serversummary += "Service not running on vCenter $($vCenterFQDN): $($NonRunningVMONService.ServiceName)"
                $VCStatus[$VCServer.Name] = "Fail"
                $VCStatusOK = $fail
                }
            else{
                if ($Log) {Write-Logfile "Non-running service $($NonRunningVMONService.ServiceName) in Ignore list"}
                }
            }
        }
   
   #Get VC HA status if configured
   
   $VCHAStatus = get-vchaconfig $VCServer
   if ($Log) {Write-Logfile "VCHA status for $($vCenterFQDN) is $($VCHAStatus)"}
   write-host "VCHA status for $($vCenterFQDN) is $($VCHAStatus)"
   if ($VCHAStatus -notmatch "Healthy"){
        if ($Log) {Write-Logfile "VCenter HA not healthy on vCenter $($vCenterFQDN)"}
        $serversummary += "VCenter HA not healthy on vCenter $($vCenterFQDN)"
        $VCStatus[$VCServer.Name] = "Fail"
        $VCStatusOK = $fail
        }
   
    #Get VC licence details
    $ThisVCsLicenseEntry = $HostAssignedLicenseArray | where {$_.Host -match $VCServer.Name -and $_.vCenter -match $VCserver}
    if ($Log) {Write-Logfile "This vCenters licence entry is $($ThisVCsLicenseEntry)"} 
    if ($Log) {Write-Logfile "This vCenters licence expiry is $($ThisVCsLicenseEntry.LicenseExpiryDate)"}
    if ($ThisVCsLicenseEntry.LicenseExpiryDate -notmatch "Never"){
        $LicenseExpiring = [math]::round((New-TimeSpan -Start (Get-Date) -End $ThisVCsLicenseEntry.LicenseExpiryDate).TotalDays,0) 
        write-host "VC licence will expire in $($LicenseExpiring) days" -ForegroundColor Red
        if ($LicenseExpiring -lt $CertificateTimeToAlert){
            if ($Log) {Write-Logfile "$($VCServer) license will expire in $($LicenseExpiring) days on $($ThisVCsLicenseEntry.LicenseExpiryDate)"}
            $serversummary += "$($VCServer) license will expire in $($LicenseExpiring) days on $($ThisVCsLicenseEntry.LicenseExpiryDate)"
            $VCStatus[$VCServer.Name] = "Fail"
            $VCStatusOK = $fail
            }
        }
   
    if ($VCServerList.Count -gt 1){
           $vCenterReplicationStatus = Get-vCSA-Replication-Status -AuthTokenValue $FuncAuthToken 
            write-host $vCenterReplicationStatus
            #Invoke-ListTopologyReplicationStatus
            if ($Log) {Write-Logfile $vCenterReplicationStatus}
            foreach ($ReplicationNode in $vCenterReplicationStatus){
                write-host "Node is $($ReplicationNode.Node)" 
                if (!$MaxReplicationItemsLagging){
                    if ($Log) {Write-Logfile "Replication lag items not set - setting to default of 100"}
                    $MaxReplicationItemsLagging = 100
                    }
                if ($ReplicationNode.status_available -match "False" -or $ReplicationNode.partner_available -match "False" -or $ReplicationNode.change_lag -gt $MaxReplicationItemsLagging){
                    write-host "Replication showing errors for $($ReplicationNode.Node) and replication partner $($ReplicationNode.replication_partner)" -ForegroundColor Red
                    if ($Log) {Write-Logfile "Replication showing errors for $($ReplicationNode.Node) and replication partner $($ReplicationNode.replication_partner)"}
                    $serversummary += "Replication not running correctly on vCenter $($vCenterFQDN): Replication partner $($ReplicationNode.replication_partner): $($vCenterReplicationStatus)"
                    $VCStatus[$VCServer.Name] = "Fail"
                    $VCStatusOK = $fail
                    }
                }
            }
        
   #Does this VC have an external PSC - if so name them
   $VC_PSCs = get-VCenter-PSC
   #If we return any PSCs check health on them
   if ($VC_PSCs){
        
        foreach ($VC_PSC in $VC_PSCs){
            $RestApiUrl = 'https://'+$VC_PSC+'/rest'
            try{
                $AuthenticationToken = Create-Session
                write-host "Creating session"
                if ($Log) {Write-Logfile "Creating session"}
                if ($AuthenticationToken.Value){
                    Start-Sleep -Seconds 2
                    $correctToken = 0
                    $FuncAuthToken = $AuthenticationToken.Value
                    }
        
                }
            catch{
                Write-Host "Wrong Username or Password" -ForegroundColor Red
                if ($Log) {Write-Logfile "Wrong Username or Password - or maybe shell is not set to bash shell"}
                Start-Sleep -Seconds 2
                }
            $vcsaHealthStatus = Get-Health-Status -AuthTokenValue $FuncAuthToken #| where {$_.Definition -contains "green"}
            $vcsaHealthStatus
            $vcsaHealth = $vcsaHealthStatus  | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Definition | where {$_ -notmatch "green"}
            $vcsaHealth
            if ($vcsaHealth){
                $serversummary += "Health Status Issue on $($VC_PSC): $($vcsaHealth)"
                $VCStatus[$VCServer.Name] = "Fail"
                $VCStatusOK = $fail
                }
            }
           
        }           
    
    
   else{
        if ($Log) {Write-Logfile "Health status"}
        $vcsaHealthStatus = Get-Health-Status -AuthTokenValue $FuncAuthToken #| where {$_.Definition -contains "green"}
        if ($Log) {Write-Logfile "$($vcsaHealthStatus)"}
        $vcsaHealth = $vcsaHealthStatus  | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Definition | where {$_ -notmatch "green"}
        if ($Log) {Write-Logfile "$($vcsaHealth)"}
        if ($vcsaHealth){
        
            $serversummary += "Health Status Issue on $($vCenterFQDN): $($vcsaHealth)"
            $VCStatus[$VCServer.Name] = "Fail"
            $VCStatusOK = $fail
        
            }
        }
    #Check disk space on vCenter
    if ($Log) {Write-Logfile "disk space"}
    $root = $VCRootCredential.UserName
    if ($Log) {Write-Logfile "Using $($VCRootCredential.UserName) to logon"}
    $cmd = "df -h"
    if (!(Test-Path "C:\PROGRA~1\PUTTY\plink.exe")) {Throw "Plink.exe is not available in the specified folder."}
    $plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
    $remoteCommand = '"' + $cmd + '"'
    $commandoutput = run-ssh-command $vCenterFQDN $VCRootCredential.UserName $VCRootCredential.Password $remoteCommand $true
    if ($commandoutput -match "Error Logging On" -or $commandoutput -match "Access Denied" -or $commandoutput -match "Using keyboard-interactive authentication"){
        $serversummary += "$($VMHost) - Error logging on to vCenter $($vCenterFQDN) using SSH"
        $VCStatusOK = $false
        }
    
    else{
        if ($commandoutput){
            foreach ($line in $commandoutput){
            if ($Log) {Write-Logfile $line}
            [int]$linelength = $line.length
            $MountPoint = $Size = $Used = $Available =$UsePercentage = $null
            if ($line -notmatch "Filesystem"){
                $MountPoint = ($line.Substring(0,42)).trim()
                $Size = ($line.Substring(43,6)).trim()
                $Used = ($line.Substring(49,5)).trim()
                $Available = ($line.Substring(54,5)).trim()
                [int]$UsePercentage = ($line.Substring(59,5)).trim().replace("%","")
                if ($Log) {Write-Logfile "$MountPoint is $UsePercentage% used"}
                if ($UsePercentage -gt $PartitionPercentFull){
                    if ($MountPoint -notlike "/dev/mapper/archive_vg-archive"){
                        $serversummary += "$($vCenterFQDN) - Disk Space on mountpoint $($MountPoint) is $($UsePercentage)% used"
                        $VCStatus[$VCServer.Name] = "Fail"
                        $VCStatusOK = $fail
                        }
                    }
                }
        
            }
        }
    else {
        if ($Log) {Write-Logfile "No output from command $($cmd) on $($vCenterFQDN) - check the shell is set to BASH shell"}
        }
    }
        

    #No use for the REST API any more so close session
    $quit = Terminate-Session -AuthTokenValue $FuncAuthToken | ft 
    
    #Check VC/PSC certificate
    try {$VCCert = Test-WebServerSSL -URL $VCServer} #| Select OriginalURi, CertificateIsValid, Issuer, @{N="Expires";E={$_.Certificate.NotAfter} }, @{N="DaysTillExpire";E={(New-TimeSpan -Start (Get-Date) -End ($_.Certificate.NotAfter)).Days} | where (DaysTillExpire -lt 30) }
    catch {Write-Output "Ran into an issue: $($PSItem.ToString())"}
    $TimeTilExpire = (New-TimeSpan -Start (Get-Date) -End ($VCCert.Certificate.NotAfter.Date)).Days
    if ($Log) {Write-Logfile "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $($TimeTilExpire) days"}
    if ($TimeTilExpire -lt $CertificateTimetoAlert -and $TimeTilExpire -ne $null){
        $serversummary += "`n`rCertificate issued to $($VCCert.OriginalURi.Host) by $($VCCert.Issuer) expires on $($VCCert.Certificate.NotAfter.Date.Date) in $TimeTilExpire days;"
        $VCStatus[$VCServer.Name] = "Fail"
        $VCStatusOK = $fail
        }
    if ($Log) {Write-Logfile "PSCs: $($VC_PSCs)"}
    if ($VC_PSCs){
        foreach ($VC_PSC in $VC_PSCs){
            $VC_PSC = $VC_PSC.split(":")[0]
            if ($VC_PSC -notmatch $VCServer.Name){
                if ($Log) {Write-Logfile "Looking for certificate on $($VC_PSC)"}  
                try {$PSCCert = Test-WebServerSSL -URL $VC_PSC}
                catch {Write-Output "Ran into an issue: $($PSItem.ToString())"} 
                $TimeTilExpire = (New-TimeSpan -Start (Get-Date) -End ($PSCCert.Certificate.NotAfter.Date)).Days
                if ($Log) {Write-Logfile "`n`rCertificate issued to $($PSCCert.OriginalURi.Host) by $($PSCCert.Issuer) expires on $($PSCCert.Certificate.NotAfter.Date.Date) in $($TimeTilExpire) days"}  
                if ($TimeTilExpire -lt $CertificateTimetoAlert -and $TimeTilExpire -ne $null){
                    $serversummary += "`n`rCertificate issued to $($PSCCert.OriginalURi.Host) by $($PSCCert.Issuer) expires on $($PSCCert.Certificate.NotAfter.Date.Date) in $TimeTilExpire days;"
                    $VCStatus[$VCServer.Name] = "Fail"
                    $VCStatusOK = $fail
                    }
                }
            }
        }
    }       
$VCStatus 

foreach($VMHost in $VMHosts){ 
    
    if ($VMHost -notin $IgnoreHosts){
        Write-Host "Processing $($VMHost)" -ForegroundColor Blue 
        if ($Log) {Write-Logfile "Processing $($VMHost)"}
        if ($Log) {Write-Logfile "$($VMHost) not in $($IgnoreHosts)"}
        $vCenter = $VMHost.Uid.Split('@')[1].Split(':')[0]
        if ($Log) {Write-Logfile $vCenter}
        #Custom object properties
        $serverObj = New-Object PSObject
        $serverObj | Add-Member NoteProperty -Name "Host" -Value $VMHost
        if ($Log) {Write-Logfile $VCStatus[$vCenter]}
        if ($VCStatus.$vCenter -eq "Fail"){
            $serverObj | Add-Member NoteProperty -Name "vCenter" -Value "Fail"
            }
        else{
            $serverObj | Add-Member NoteProperty -Name "vCenter" -Value "Pass"
            }       
        #Null and n/a the rest, will be populated as script progresses
        $serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
        $serverObj | Add-Member NoteProperty -Name "VMs" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "OVC Alarms" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Services" -Value $null
        $serverObj | Add-Member NoteProperty -Name "Network" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Hardware" -Value "n/a"
        $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "n/a"
        $VCURL = "HTTPS://$vCenter/ui"

        #DNS Check
        Write-Host "DNS Check: " -NoNewline;
        if ($Log) {Write-Logfile "DNS Check: "}
        try {$ip = @([System.Net.Dns]::GetHostByName($VMHost).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)}
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
            try {$ping = Test-Connection $VMHost -Quiet -ErrorAction Stop}
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
                    $serversummary += "$($VMHost) - Ping Failed"
                    }
                }
            }
        
        #Uptime Check
        Write-Host "Uptime (hrs): " -NoNewline
        $boottime = Get-View -ViewType hostsystem -Property name,runtime.boottime | where {$_.Name -eq $VMHost.Name} #|  Select-Object Name,($_.runtime).BootTime
        if ($Log) {Write-Logfile "Uptime (hrs): "}
        [int]$uptimehours = $null
        if ($Log) {Write-Logfile "Boot time is $($boottime.runtime.boottime.datetime)"}
        $BootUTCTime = $boottime.runtime.boottime.datetime
        if ($Log) {Write-Logfile "Boot time (UTC) is $($BootUTCTime)"}
        if ($Log) {Write-Logfile "Date/time UTC now is $((Get-Date).ToUniversalTime())"}
        $uptimehours = [math]::round((New-TimeSpan -Start $BootUTCTime -End ((Get-Date).ToUniversalTime())).TotalHours,0) #| Select-Object -ExpandProperty Days
        if ($Log) {Write-Logfile "up for $($uptimehours)"}
        if ($Log) {Write-Logfile "Minimum uptime is $($MinimumUptime)"}
        [int]$uptime = "{0:00}" -f $timespan.TotalHours
        if ($uptimehours -lt $MinimumUptime){
           Write-Host -ForegroundColor $warn "Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           $serversummary += "$($VMHost) - Uptime is less than $($MinimumUptime) hours ($($uptimehours))"
           }
        else{
            Write-Host -ForegroundColor $pass "Uptime is more than $($MinimumUptime) hours ($($uptimehours))"
            }
        $serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptimehours -Force 
        
        ## VMHost Alarms
        Write-Host "Host Alarms: " -NoNewline
        if ($Log) {Write-Logfile "Checking for active VMware host alarms"}
        $VMHAlarms = @()
        $VMHostStatus = Get-View -ViewType hostsystem -Property Name,OverallStatus,ConfigStatus,TriggeredAlarmState  | where {$_.Name -eq $VMHost.Name} | where {$_.OverallStatus -ne "Green" -or $_.ConfigStatus -ne "Green"} | Select-Object Name,OverallStatus,ConfigStatus,TriggeredAlarmState | sort -property Name | get-unique
        if ($VMHostStatus){
            foreach($TriggeredAlarm in ($VMHostStatus.TriggeredAlarmstate | sort | get-unique)){
                foreach ($Alarm in ($TriggeredAlarm.Alarm| sort | get-unique)){
                    $TriggeredAlarmName = (Get-AlarmDefinition -Id $Alarm) | get-unique | select $_.Name
                    if ($Log) {Write-Logfile "Triggered alarm name is $($TriggeredAlarmName)"}
                    if ($TriggeredAlarmName -notin $IgnoreHostAlarms){
                        if ($Log) {Write-Logfile "$TriggeredAlarmName not in $($IgnoreHostAlarms)"}
                        $Hprops = @{
                            Host = $VMHostStatus.Name
                            OverAllStatus = $VMHostStatus.OverallStatus
                            TriggeredAlarms = (Get-AlarmDefinition -Id $Alarm).Name | sort | get-unique
                            }
                        $VMHAlarms += New-Object PSObject -Property $Hprops
                        }
                    else{
                        if ($Log) {Write-Logfile "$TriggeredAlarmName in $($IgnoreHostAlarms)"}
                        }
                    }
                }
        
            if (!($VMHostStatus.TriggeredAlarmState) -and ($VMHostStatus.OverallStatus -ne "Green")){
                $Hprops = @{
                            Host = $VMHostStatus.Name
                            OverAllStatus = $VMHostStatus.OverallStatus
                            TriggeredAlarms = "Host Error - configuration issue(s)"
                            }
                $VMHAlarms += New-Object PSObject -Property $Hprops
                }
            }
    
    
    
        if ($VMHAlarms){
            if ($Log) {Write-Logfile "$($VMHost) - Host Alarm(s): $($VMHAlarms.TriggeredAlarms)"}
            Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($VMHost) - Host Alarm(s): $($VMHAlarms.TriggeredAlarms)";$serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Fail" -Force
            }
        else{
            if ($Log) {Write-Logfile "No active alarms for Host"}
            Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Host Alarms" -Value "Pass" -Force
            }
    
    
        #VM Alarms Check
        Write-Host "VM Alarms: " -NoNewline
        if ($Log) {Write-Logfile "Checking for active VM alarms"}
        $VMAlarms = @()
        $VMStatus = ($VMHost |Get-VM | Get-View) | where {$_.Name -notin $IgnoreVMs} | where {$_.OverallStatus -ne "Green" -or $_.ConfigStatus -ne "Green" } | Select-Object Name,OverallStatus,ConfigStatus,TriggeredAlarmState | sort -property Name | get-unique
        if ($VMStatus) {
            foreach ($TriggeredAlarm in ($VMStatus.TriggeredAlarmstate | sort | get-unique)) {
                foreach ($Alarm in ($TriggeredAlarm.Alarm| sort | get-unique)){
                    if ($Log) {Write-Logfile "Alarm is $($Alarm)"}
                    if ($Log) {Write-Logfile "vCenter is $($vcenter)"}
                    $FullAlarmDetails = Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter}
                    $TriggeredAlarmName = Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter} #| sort -property Name | get-unique | select $_.Name
                    if ($Log) {Write-Logfile "Triggered alarm name is $($TriggeredAlarmName)"}
                    if ($TriggeredAlarmName -notin $IgnoreVMAlarms){
                        if ($Log) {Write-Logfile "$TriggeredAlarmName not in $($IgnoreVMAlarms)"}
                        $VMprops = @{
                            VM = $VMStatus.Name
                            OverallStatus = $VMStatus.OverallStatus
                            TriggeredAlarms = (Get-AlarmDefinition -Id $Alarm | where {$_.Uid -match $vCenter}).Name #| sort | get-unique
                            }
                        $VMAlarms += New-Object PSObject -Property $VMprops
                        }
                    else{
                        if ($Log) {Write-Logfile "$TriggeredAlarmName in $($IgnoreVMAlarms)"}
                        }
                    }
                }
            }
    
        if ($VMAlarms){
            if ($Log) {Write-Logfile "$($VMHost) ($($VMAlarms.VM)) - VM Alarm(s): $($VMAlarms.TriggeredAlarms)"}
            Write-Host -ForegroundColor $fail "Fail"; $serversummary += "$($VMHost) ($($VMAlarms.VM)) - VM Alarm(s): $($VMAlarms.TriggeredAlarms)";$serverObj | Add-Member NoteProperty -Name "VM Alarms" -Value "Fail" -Force
            }
        else{
            if ($Log) {Write-Logfile "No active alarms for VM"}
            Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "VM Alarms" -Value "Pass" -Force
            }
    
        #VMs Check
        Write-Host "VMs: " -NoNewline
        $VMErrors = @()
        $HostVMs = ($VMHost |Get-VM | Get-View)
    
        $BadVMs = $HostVMs  | where {$_.RunTime.ConnectionState -ne "connected"} | where {$_.Name -notin $IgnoreVMs} | select name 
        if ($BadVMs){
            $VMErrors += "Bad Connection State VM(s): $($BadVMs.Name)"
            }
        #Check for powered off VMs - there may be legitimate reasons for VMs to be powered off- to not check for this change the $CheckPowerOffVMs variable to $false in the Variables section
        if ($CheckPowerOffVMs){
            $PoweredOffVMs = $HostVMs | where {$_.RunTime.PowerState -eq ’PoweredOff’} | where {$_.Name -notin $IgnoreVMs} | select name 
            if ($PoweredOffVMs){
                $VMErrors += "Powered Off VM(s): $($PoweredOffVMs.Name)"
                }
            }
        Switch (!$VMErrors) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "VMs" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $VMErrors; $serversummary += "$($VMHost) - VM Error(s) $($VMErrors)";$serverObj | Add-Member NoteProperty -Name "VMs" -Value "Fail" -Force}
            }

         
    
        #Host Services

        Write-Host "Host Services: " -NoNewline
        if ($Log) {Write-Logfile "Host Services: "}
        $ServiceErrors = $null
        if($VMHost.ConnectionState -eq "Maintenance"){
	        write-host "The host is in maintenance mode"
	        if ($Log) {Write-Logfile "$($VMHost) is in maintenance mode"}
            Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force
            $serverObj | Add-Member NoteProperty -Name "Host" -Value "$($VMHost) (Maintenance)" -Force
            }
        else{
            $ServiceErrors +=  Check_VMHost_Running_Services $VMHost
            Switch (!$ServiceErrors) {
                $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Pass" -Force}
                default { Write-Host -ForegroundColor $fail "$($ServiceErrors) not running"; $serversummary += "$($VMHost) - Service(s) $($ServiceErrors) not running";$serverObj | Add-Member NoteProperty -Name "Services" -Value "Fail" -Force}
                }
            }
        
        #Check Networks
        write-host "Network: " -NoNewLine
        if ($Log) {Write-Logfile "Network: "}
        $NetworkErrors = @()
        
        #Check all switches have enough ports
        $vSwitchPortsLeft = 10

        if ($Log) {Write-Logfile "Port groups on DV switches"}
        $Result = $VMHost | Get-VirtualSwitch -Standard | Sort NumPortsAvailable | Where {$_.NumPortsAvailable -lt $($vSwitchPortsLeft)} | Select Name, NumPortsAvailable
        
        if ($Result){
            $NetworkErrors += "Switch(es) $($Result.Name) on  $($VMHost) has less than $($vSwitchPortsLeft) available"
            if ($Log) {Write-Logfile "Switch(es) $($Result.Name) on $($VMHost) less than $($vSwitchPortsLeft) ports available"}
            }

        if ($vdspg = $VMHost |Get-VDSwitch | Sort-Object -Property Name | Get-VDPortgroup)
           {
                if ($Log) {Write-Logfile "Port groups on DV switches"}
                if ($Log) {Write-Logfile $vdspg}
            
                $ImpactedDVS = @() 
                Foreach ($PG in $vdspg | Where-Object {-not $_.IsUplink -and $_.PortBinding -ne 'Ephemeral' -and -not ($_.PortBinding -eq 'Static' -and $_.ExtensionData.Config.AutoExpand)} )
                {
                    if ($Log) {Write-Logfile "Processing $($PG)"}
                    $NumPorts = $PG.NumPorts
                    $NumVMs = ($PG.ExtensionData.VM).Count
                    $OpenPorts = $NumPorts - $NumVMs
                    if ($Log) {Write-Logfile "$($PG) has $($OpenPorts) open ports"}
                    If ($OpenPorts -lt $vSwitchPortsLeft)
                    {
                        $myObj = "" | select vDSwitch,Name,OpenPorts
                        $myObj.vDSwitch = $PG.VDSwitch
                        $myObj.Name = $PG.Name
                        $myObj.OpenPorts = $OpenPorts
                        $ImpactedDVS += $myObj
                    }
                }
                if ($ImpactedDVS){
                    $NetworkErrors += "Switch(es) $($ImpactedDVS) on  $($VMHost) has less than $($vSwitchPortsLeft) available"
                    if ($Log) {Write-Logfile "Switch(es) PortGroups $($ImpactedDVS.Name) on  $($VMHost) has less than $($vSwitchPortsLeft) available"}
                    }
            
                
            }

        #Find this hosts cluster (if it has one) and examine it's config
        #If the host is in a cluster check for vMotion enabled
        $ThisCluster = Get-cluster -VMHost $VMHost
        #Lookup license key and it's capabilities and check for expiration
        if ($Log) {Write-Logfile "License for this host is $($VMHost.LicenseKey)"}
        if ($VMHost.LicenseKey){
            $LicenseRecord = $VCLicenseArray | where {$_."vCenter" -match $vCenter -and $_."LicenseKey" -match $VMHost.LicenseKey}
            $ThisHostsLicenseEntry = $HostAssignedLicenseArray | where {$_.Host -match $VMHost.Name -and $_.vCenter -match $vCenter}
            if ($Log) {Write-Logfile "This hosts licence entry is $($ThisHostsLicenseEntry)"} 
            if ($LicenseRecord.Name -match "Product Evaluation"){
                if ($ThisHostsLicenseEntry.LicenseExpiryDate){
                    $LicenseExpiring = [math]::round((New-TimeSpan -Start (Get-Date) -End $ThisHostsLicenseEntry.LicenseExpiryDate).TotalDays,0)
                    if (!$IgnoreEvaluationLicences){
                        $NetworkErrors += "$($VMHost) Evaluation license in use - expiry date $($ThisHostsLicenseEntry.LicenseExpiryDate) IN $($LicenseExpiring) DAYS"
                        }
                    else{
                        if ($LicenseExpiring -lt $CertificateTimeToAlert){
                            $NetworkErrors += "$($VMHost) license will expire in $($LicenseExpiring) days on $($ThisHostsLicenseEntry.LicenseExpiryDate)"
                            }
                        }
                    }
                else{
                    if (!$IgnoreEvaluationLicences){
                        $NetworkErrors += "$($VMHost) Evaluation license in use - expiry date not available"
                        }
                    }
                }
            else{
                if ($Log) {Write-Logfile "This hosts licence expiry is $($ThisHostsLicenseEntry.LicenseExpiryDate)"}
                if ($ThisHostsLicenseEntry.LicenseExpiryDate -notmatch "Never"){
                    $LicenseExpiring = [math]::round((New-TimeSpan -Start (Get-Date) -End $ThisHostsLicenseEntry.LicenseExpiryDate).TotalDays,0) 
                    write-host "Host licence will expire in $($LicenseExpiring) days" -ForegroundColor Red
                    if ($LicenseExpiring -lt $CertificateTimeToAlert){
                        $NetworkErrors += "$($VMHost) license will expire in $($LicenseExpiring) days on $($ThisHostsLicenseEntry.LicenseExpiryDate)"
                        }
                    }
                  
                }
            
            if ($Log) {Write-Logfile "License Name is $($LicenseRecord.Name)"}
            if ($Log) {Write-Logfile "License Key is $($LicenseRecord.LicenseKey)"}
            if ($Log) {Write-Logfile "vCenter is $($LicenseRecord.vCenter)"}
            $licenseFeatures = @{}
            $licenseFeatures = $LicenseRecord.licenseFeatures.Value
            $DRSLicensed = $false
            $HALicensed = $false
            foreach ($licenseFeature in $licenseFeatures){
                switch($licenseFeature.Key){
                            "drs" {$DRSLicensed = $true;if ($Log) {Write-Logfile "DRS is licensed"}}
                            "dr" {$HALicensed = $true;if ($Log) {Write-Logfile "HA is licensed"}}
                
                        }
                   }
        
            if ($ThisCluster){
                $vMotionenabled = $VMHost | Get-VMHostNetworkAdapter |  Where {$_.VMotionEnabled}
                if ($Log) {Write-Logfile "Host is in cluster $($ThisCluster)"}
        
                if (!$vMotionenabled){
                    #Check if this is the only host in this datacenter
                    $VMDatacenter = Get-Datacenter -VMHost $VMHost
                    if ($Log) {Write-Logfile "dataCenter is $($VMDatacenter.Name)"}
                    if (($VCDatacenters | where {$_.Name -match $VMDatacenter.Name}).NumberofHosts -gt 1) {
                        if ($Log) {Write-Logfile "more than 1 on dc"}
                        if ($Log) {Write-Logfile "No vMotion Network on $VMHost"}
                        $NetworkErrors += "No vMotion Network on $VMHost"
                        }
                    }
                if ($Log) {Write-Logfile "Cluster is $($ThisCluster)"}
                #Check if the cluster has more than 2 hosts (if not ignore HA/DRS settings)
                $VMCluster = $VCClusters | where {$_.Name -match $ThisCluster}
                if ($VMCluster.NumberofHosts -gt 1) {
                    if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) has more than 1 host so investigate HA and DRS settings"}
                    if (!$VMCluster.DrsEnabled) {
                        if ($DRSLicensed){
                            $NetworkErrors += "Cluster $($VMCluster.Name) for $($VMHost) does not have DRS enabled but it is licensed"
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have DRS enabled but it is licensed"}
                            }
                        else{
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have DRS enabled and it is not licensed"}
                            }
                        }
                    if (!$VMCluster.HAEnabled) {
                        if ($HALicensed){
                            $NetworkErrors += "Cluster $($VMCluster.Name) for $($VMHost) does not have HA enabled but it is licensed"
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have HA enabled but it is licensed"}
                            }
                        else{
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have HA enabled and it is not licensed"}
                            }
                        }
        
                    if (!$VMCluster.HAAdmissionControlEnabled) {
                        if ($HALicensed){
                            $NetworkErrors += "Cluster $($VMCluster.Name) for $($VMHost) does not have HA Admission Control enabled but it is licensed"
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have HA Admission Control enabled but it is licensed"}
                            }
                        else{
                            if ($Log) {Write-Logfile "Cluster $($VMCluster.Name) for $($VMHost) does not have HA Admission Control enabled and it is not licensed"}
                            }
                        }
        
                }
       
            }
            else{
                if ($Log) {Write-Logfile "Host is not in any cluster"}
                }
        
            }
        else{
            if ($Log) {Write-Logfile "$($VMHost) does not have a license key allocated"}
            $NetworkErrors += "$($VMHost) does not have a license key allocated"
            }
        Switch (!$NetworkErrors) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Network" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $NetworkErrors; $serversummary += "$($VMHost) - VMware Host Network Error(s) $($NetworkErrors)";$serverObj | Add-Member NoteProperty -Name "Network" -Value "Fail" -Force}
            }
    
        #Hardware Health
        Write-Host "Host Hardware: " -NoNewline
        if ($VMHost -in $IgnoreHardwareErrors){
            if ($Log) {Write-Logfile "Host in $($IgnoreHardwareErrors) array - Not checking for hardware errors on $($VMHost)"}
            $HardwareErrors = $null
            } 
        else{
            if ($Log) {Write-Logfile "Host Hardware: "}
            $HardwareErrors = @()
            $hs = $SensorInfo = $MemoryInfo = $CPUInfo= $StorageInfo = $null
            if ($IPMIHardwareErrors){
                #DO IPMI stuff
                $esxcli = Get-VMHost $VMHost | Get-EsxCLI -V2
                $ESXiVersion = $null
                $ESXiVersion = $esxcli.system.version.get.Invoke()
                if ($Log) {Write-Logfile "Build is $($ESXiVersion.Build)"}
                if ($Log) {Write-Logfile "Patch is $($ESXiVersion.Patch)"}
                if ($Log) {Write-Logfile "Product is $($ESXiVersion.Product)"}
                if ($Log) {Write-Logfile "Update is $($ESXiVersion.Update)"}
                if ($Log) {Write-Logfile "Version is $($ESXiVersion.Version)"}
                $MajorVersion = $null
                $MajorVersion = "$($ESXiVersion.Version.split(".")[0]).$($ESXiVersion.Version.split(".")[1])"
                if ($MajorVersion -gt 6.5){
                    $IPMI = $esxcli.hardware.ipmi.bmc.get.Invoke()
                    if ($Log) {Write-Logfile "IPMI address is $($IPMI.IPv4Address)"}
                    if ($Log) {Write-Logfile "IPMI manufacturer is $($IPMI.Manufacturer)"}
        
                    switch -wildcard ($IPMI.Manufacturer){
                        "Hewlett*"{
                            if ($Log) {Write-Logfile "HP so running ILO checks"}
                            $HardwareErrors += Get_ILO_Health $IPMI.IPv4Address $False
                            }
                        "Dell Inc." {
                            if ($Log) {Write-Logfile "Dell so running iDRAC checks"}
                            $HardwareErrors += Get_Idrac_Health $IPMI.IPv4Address $False
                            }
                        default {
                            if ($Log) {Write-Logfile "No IPMI type found - not running any IPMI checks"}
                            }
                        }

                    }
                else{
                    write-host "Major Version is not higher than 6.5 - unable to get IPMI address - not running any IPMI checks"
                    if ($Log) {Write-Logfile "Major Version is not higher than 6.5 - unable to get IPMI address -  - not running any IPMI checks"}
                    }
                }
            $hs = Get-View -ViewType hostsystem -Property ConfigManager.HealthStatusSystem | where {$_.Name -eq $VMHost.Name} 
            $SensorInfo = $hs.Runtime.SystemHealthInfo.NumericSensorInfo | where{$_.HealthState.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} | Select @{N='Host';E={$VMHost.Name}},Name,@{N='Health';E={$_.HealthState.Label}}
            if ($SensorInfo){
                $HardwareErrors += $SensorInfo
                }
            $MemoryInfo = $hs.Runtime.HardwareStatusInfo.MemoryStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
            if ($MemoryInfo){
                $HardwareErrors += "Memory Fault $($MemoryInfo.Summary)"
                }
            $CPUInfo = $hs.Runtime.HardwareStatusInfo.CPUStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
            if ($CPUInfo){
                $HardwareErrors += "CPU Fault $($CPUInfo.Summary)"
                }
            $StorageInfo = $hs.Runtime.HardwareStatusInfo.StorageStatusInfo.Status | where{$_.Label -notmatch "Green|Unknown" -and $_.Name -notmatch 'Rollup'} 
            if ($StorageInfo){
                $HardwareErrors += "Storage Fault $($StorageInfo.Summary)"
                }
            
            #Find bad paths on HBAs
            
            [ARRAY]$HBAs = $VMHost | Get-VMHostHba -Type "FibreChannel"
            if ($HBAs){
                if ($Log) {Write-Logfile "Examining HBAs on $($VMHost)"}
        
                $BadHBAStates = $HBApathstates | where {$_.VMHost -match $VMHost -and ($_.Dead -gt 0 -or $_.Inactive -gt 0)}
                if ($Log) {Write-Logfile "$($BadHBAStates)"}
                foreach ($BadHBAState in $BadHBAStates){
                    $HardwareErrors += "There are dead/standby/inactive paths on $($BadHBAState.HBA) on $($VMHost)"
                    if ($Log) {Write-Logfile "There are dead/standby/inactive paths on $($BadHBAState.HBA) on $($VMHost)"}
                    }
                
                }
         
            #Is the SD card adapter working?
            if ($Log) {Write-Logfile "Examining SD Storage Adapter on $($VMHost)"}
            $BadSDStates = $SDstates | where {$_.VMHost -match $VMHost -and ($_.Dead -gt 0)}
            if ($Log) {Write-Logfile "$($BadSDStates)"}
            foreach ($BadSDState in $BadSDStates){
                $HardwareErrors += "$($BadSDState.HBA) on $($VMHost) is not working correctly"
                if ($Log) {Write-Logfile "$($BadSDState.HBA) on $($VMHost) is not working correctly"}
                }
        
        
            }
        
        Switch (!$HardwareErrors) {
            $true { Write-Host -ForegroundColor $pass "Pass";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Pass" -Force}
            default { Write-Host -ForegroundColor $fail $HardwareErrors; $serversummary += "$($VMHost) - VMware Host Hardware Error(s) $($HardwareErrors)";$serverObj | Add-Member NoteProperty -Name "Hardware" -Value "Fail" -Force}
            }
    
        #Disk Space
        Write-Host "Disk Space: " -NoNewline
        if ($Log) {Write-Logfile "Disk Space: "}
        if ($VMHost -in $IgnoreHostsDiskSpace){
            if ($Log) {Write-Logfile "Host in $IgnoreHostsDiskSpace array - Not checking for disk space on $($VMHost)"}
            $DiskSpaceOK = $true
            }   
        else{
            $DiskSpaceOK = $true
            $root = "root"
            $cmd = "vdf -h"
            if (!(Test-Path "C:\PROGRA~1\PUTTY\plink.exe")) {Throw "Plink.exe is not available in the specified folder."}
            $plink = "echo y | C:\PROGRA~1\PUTTY\plink.exe"
            $remoteCommand = '"' + $cmd + '"'
            $commandoutput = run-ssh-command $VMHost $ESXiMonitorCredential.UserName $ESXiMonitorCredential.Password $remoteCommand $false
            if ($Log) {Write-Logfile "Output is $($commandoutput)"}
            if ($commandoutput -match "Error Logging On" -or $commandoutput -match "Access Denied" -or $commandoutput -match "Using keyboard-interactive authentication"){
                $serversummary += "$($VMHost) - Error logging on to VM Host using SSH"
                $DiskSpaceOK = $false
                }
    
            else{
                foreach ($line in $commandoutput){
        
                    [int]$linelength = $line.length
                    $MountPoint = $Size = $Used = $Available =$UsePercentage = $null
                    if ($linelength -eq 58){
                        $MountPoint = ($line.Substring(0,24)).trim()
                        $Size = ($line.Substring(25,6)).trim()
                        $Used = ($line.Substring(31,10)).trim()
                        $Available = ($line.Substring(41,10)).trim()
                        [int]$UsePercentage = ($line.Substring(51,5)).trim().replace("%","")
                        if ($Log) {Write-Logfile "$MountPoint is $UsePercentage % used"}
                        if ($UsePercentage -gt $PartitionPercentFull -and $MountPoint -notmatch "upgradescratch"){
                            $serversummary += "$($VMHost) - Disk Space on mountpoint $($MountPoint) is $($UsePercentage) % used"
                            $DiskSpaceOK = $false
                            }
                        }
        
                    }
                }
            }
        ## Datastore Functions
        if ($Log) {Write-Logfile "Checking for datastores below $($datastorePercentFree)% free space"}
        $DSReport = $VMHost | Get-Datastore | Select-Object Name,@{N="UsedSpaceGB";E={[math]::Round(($_.CapacityGB),2)}},@{N="FreeSpaceGB";E={[math]::Round(($_.FreeSpaceGB),2)}},@{N="%Free";E={[math]::Round(($_.FreeSpaceGB)/($_.CapacityGB)*100,2)}}
        $DSBelow = $DSReport | Where-Object {$_."%Free" -lt $($datastorePercentFree)} | Select-Object Name,"%Free"
        if ($DSBelow) {
            $serversummary += "$($VMHost) - Disk Space on Datastore(s) is below $($datastorePercentFree)%: $($DSBelow.Name) ($($DSBelow."%Free")%)"
            $DiskSpaceOK = $false
            }
    
        Switch ($DiskSpaceOK) {
            $false { Write-Host -ForegroundColor $fail "Fail"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Fail" -Force}
            $true { Write-Host -ForegroundColor $pass "Pass"; $serverObj | Add-Member NoteProperty -Name "Disk Space" -Value "Pass" -Force}
            }

            
        #Add this servers output to the $report array
        $report = $report + $serverObj
    
        }
    else{
        Write-Host "Ignoring $($VMHost)" -ForegroundColor Blue
        if ($Log) {Write-Logfile "Ignoring $($VMHost)"}
        Write-Host "$($VMHost) in $($IgnoreHosts)" -ForegroundColor Blue 
        
        }
    }         

}

else{
    $serversummary += "$($VCServer) - Cannot access vCenter"
    }
### Begin report generation

if (Test-Path "$($OutputFolder)\VMware_Error_Status_Fail.txt"){
            del "$($OutputFolder)\VMware_Error_Status_Fail.txt"
            }

if ($ReportMode -or $SendEmail)
{
    #Get report generation timestamp
    $reportime = (Get-Date).ToString("dd/MM/yyyy HH:mm")
    if ($IgnoreHosts){
        $ignoretext = "Configured to ignore hosts: $($IgnoreHosts)."
        }
    if ($IgnoreVMs){
        $ignoretext = $ignoretext + "Configured to ignore VMs: $($IgnoreVMs)."
        }
    if ($IgnoreVMAlarms){
        $ignoretext = $ignoretext + "Configured to ignore VM Alarms: $($IgnoreVMAlarms)."
        }
    if ($IgnoreHostAlarms){
        $ignoretext = $ignoretext + "Configured to ignore Host Alarms: $($IgnoreHostAlarms)."
        }
    if ($IgnoreHostsDiskSpace){
        $ignoretext = $ignoretext + "Configured to not logon to : $($IgnoreHostsDiskSpace)."
        }
    if (!$CheckPowerOffVMs){
        $ignoretext = $ignoretext + "Configured to ignore powered-off VMs."
        }
    if ($IgnoreHardwareErrors){
        $ignoretext = $ignoretext + "Configured to ignore hardware errors on : $($IgnoreHardwareErrors)."
        }  
    if ($IgnoreVCServices){
        $ignoretext = $ignoretext + "Configured to ignore VC service status : $($IgnoreVCServices)."
        } 
    if ($Log) {Write-Logfile "Ignore set is $($ignoretext)"}
    #Create HTML Report
                  
    #Check if the server summary has 1 or more entries
    if ($($serversummary.count) -gt 0)
    {
        #Set alert flag to true
        $alerts = $true
        # Create the error status file (if not already there)
        
        Out-File -FilePath "$($OutputFolder)\VMware_Error_Status_Fail.txt"
        #Generate the HTML
        $coloredheader = "<h1 align=""center""><a href=$ReportURL class=""blink"" style=""color:$fail"" target=""_blank"">$reportsubject</a></h1>"
        $serversummaryhtml = "<h3>VMware Health Details</h3>
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
        $serversummaryhtml = "<h3>VMware Health Details</h3>
                        <p>$ignoretext</p>
                        <p>No VMware  health errors or warnings.</p>"
    }
    
    #Common HTML head and styles
    $htmlhead="<html>
                <head>
                <title>VMware GreenScreen - $servicestatus</title>
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
        
    #VMware Health Report Table Header
    $htmltableheader = "<h3>VMware Health Summary</h3>
                        <p>
                        <table>
                        <tr>
                        <th>Host</th>
                        <th>vCenter</th>
                        <th>DNS</th>
                        <th>Ping</th>
                        <th>Uptime</th>
                        <th>VMs</th>
                        <th>Host Alarms</th>
                        <th>VM Alarms</th>
                        <th>Services</th>
                        <th>Network</th>
                        <th>Hardware</th>
                        <th>Disk Space</th>
                        </tr>"

    #VMware Health Report Table
    
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
    foreach ($reportline in $failreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "vcenter")
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VM Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Services")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Network")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Hardware")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Disk Space")
        $htmltablerow += "</tr>"
        
        $serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
    
    
        }
    
     #Add passes after so they show up last
    foreach ($reportline in $passreport){
        $htmltablerow = "<tr>"
        $htmltablerow += "<td>$($reportline.host)</td>"
        $htmltablerow += (New-ServerHealthHTMLTableCell "vcenter")
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

        $htmltablerow += (New-ServerHealthHTMLTableCell "VMs")
        $htmltablerow += (New-ServerHealthHTMLTableCell "Host Alarms")
        $htmltablerow += (New-ServerHealthHTMLTableCell "VM Alarms")
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
            #Send email message - there are alerts and the alertsonly is set to false
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

