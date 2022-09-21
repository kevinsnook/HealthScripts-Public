#...................................
# Variables
#...................................

#Max hours to go back and alert in logs
$MaxHoursToScanLog = 12

#Warn if uptime is below this number of hours
$MinimumUptime = 2                                      	

#Vcenter server to monitor (will monitor all connected vCenters)
$VCServer = "vcenter.domain.com"

#Number of days back before we alert about a cert being about to expire
$CertificateTimeToAlert = 20        				

#Set to true to alert on powered off VMs
$CheckPowerOffVMs = $false

#Minimum Percentage free on datastores before raising alert
#$datastorePercentFree = 10
$datastorePercentFree = 7

#Maximum Percentage full on Host/vCenter partitions before raising alert
$PartitionPercentFull = 90

#Comma separated array of Hosts to ignore (if host has permananent known condition or is offline) (Please ensure this is exactly the same case and format as the hostname(s))
$IgnoreHosts = @("server1.domain.net","server2.domain.net")

#Comma separated array of VMs to ignore (if VM has permanent known condition or is offline) (Please ensure this is exactly the same case and format as the VM name(s))
$IgnoreVMs = @("server14.domain.net","server22.domain.net")

#Comma separated array of VM alarms to ignore
$IgnoreVMAlarms = @("Virtual machine memory usage","Virtual machine CPU usage")

#Comma separated array of Host alarms to ignore
$IgnoreHostAlarms = @("Virtual machine memory usage","Virtual machine CPU usage","Host memory usage","Host hardware power status")

#Comma separated array of hosts with hardware errors to ignore
$IgnoreHardwareErrors = @("badserevr@domain.com","anotherserver@domain.com")

#Run IPMI Checks
$IPMIHardwareErrors = $true

#Comma separated array of vCenter services to ignore
$IgnoreVCServices = @("updatemgr")

#Path to PuttyLink executable
$PuttyLinkPath = "C:\PROGRA~1\PUTTY\plink.exe"

#Number of items not replicated before alert raised
$MaxReplicationItemsLagging = 100


#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\vmware\VMware_health.log"
#Location of transcript file for script (shows command line output for script
$TranscriptFile = "C:\Source\Scripts\vmware\VMware_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "VMware Health"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING/Monitor/VMwareHealth.html" 
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file described in $ReportFile
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\VMwareHealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$true
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true


#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "someone@domain.com"
#Send email from this address
$fromaddress = "someone-Alerts@domain.com"
#Send email using this relay host
$smtpserver = "smtp.domain.com"


#...................................
#Credentials
#....................................

#VMware SSO Credential 
$Credential = Import-CliXml -Path c:\source\scripts\Credentials\admin@sso.xml
#vCenter Credential
$VCCredential = Import-CliXml -Path c:\source\scripts\Credentials\vcenter_admin.xml
#Monitoring credential on ESXi Hosts
$ESXiMonitorCredential = Import-CliXml -Path c:\source\scripts\Credentials\monitoring-user_cred.xml
#Root credential on vCenter
$VCRootCredential = Import-CliXml -Path c:\source\scripts\Credentials\vc_root_cred.xml
#HP ILO credential
$ILOCredential = Import-CliXml -Path c:\source\scripts\Credentials\hpeilo.xml
#Dell iDRAC credential
$iDRACCredential = Import-CliXml -Path c:\source\scripts\Credentials\idrac_root.xml


