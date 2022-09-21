#Max hours to go back and alert in logs
$MaxHoursToScanLog = 1
#Warn if uptime is below this number of hours
$MinimumUptime = 1
#Number of days back before we alert about a cert being about to expire
$CertificateTimeToAlert = 30
#Fill in WIndows servers to monitor
$targets = "ory1-eud-cvma01.eu.cobham.net","tnf1-eud-cvma01.eu.cobham.net","YUL1-NAD-CVMA11.na.cobham.net"
#$targets = "ory1-eud-cvma01.eu.cobham.net","tnf1-eud-cvma01.eu.cobham.net"
#Minimum Percentage free on volumes before raising alert
$volumePercentFree = 0.05
#Maximum Percentage CPU usage before raising alert
$CPUUsagePercent = 90
#Minimum Percentage Free Memory usage before raising alert
$MemoryFreeUsagePercent = 10
#Comma separated array of network interfaces to be ignored
$IgnoreNetworkFailures = @("Embedded LOM 1 Port 4","Embedded LOM 1 Port 3","Embedded FlexibleLOM 1 Port 2","Embedded FlexibleLOM 1 Port 1")
#Comma separated array of IP addresses to NOT ping (by default GreenScreen will ping all addresses on each server)
$IgnoreIPaddresses = @("10.216.7.4","10.191.129.74","10.191.131.130","10.191.129.234","10.233.33.34")
#Comma separated array of server event numbers to ignore
#$IgnoreServerEvents = @("10016")
#Comma separated array of servers to not log disk space
#$IgnoreServerDiskSpace = @("boh2-eud-cvma01.eu.cobham.net","boh2-eud-cvma02.eu.cobham.net")
#Comma separated array of servers to not log hardware errors
#$IgnoreHardwareErrors = @("boh2-eud-cvma01.eu.cobham.net","boh2-eud-cvma02.eu.cobham.net")
#Services to monitor
#$DesiredStateServices = @("GxBlr(Instance001)","GxClMgrS(Instance001)","GxCVD(Instance001)","GXMMM(Instance001)","GxFWD(Instance001)")
$DesiredStateServices = @("GxClMgrS(Instance001)","GxCVD(Instance001)","GXMMM(Instance001)","GxFWD(Instance001)")

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\windows\windows_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\windows\windows_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "Windows Health (CACm)"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://ORY1-EUD-VMAN01\Monitor\windowshealth.html"
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file (see $ReportFile)
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\windowshealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$true
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true

#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "ITS.Datacentre.Services@cobham.com","CAC.IT.Notifications@cobham.com"
#$recipients = "kevin.snook@cobham.com"
#Send email from this address
$fromaddress = "CACm-Windows-Alerts@cobham.com"
#Send email using this relay host
$smtpserver = "smtp.eu.cobham.net"

#Credentials
#Credential for IPMI
#$IPMICredential = Import-CliXml -Path c:\source\scripts\hpeloginonly.xml
$IPMICredential = Import-CliXml -Path c:\source\scripts\Credentials\SVC-VMVRRW-001\hpeilo.xml
#Credential for Servers
#$Credential = Import-CliXml -Path c:\source\scripts\ks_cred.xml
$Credential = Import-CliXml -Path c:\source\scripts\Credentials\SVC-VMVRRW-001\SVC-VMVRRW-001.xml