#Max hours to go back and alert in logs
$MaxHoursToScanLog = 1
#Warn if uptime is below this number of hours
$MinimumUptime = 1
#Number of days back before we alert about a cert being about to expire
$CertificateTimeToAlert = 30
#Fill in WIndows servers to monitor
$targets = "server1.domain.net","server2.domain.net","server3.domain.net"
#Minimum Percentage free on volumes before raising alert
$volumePercentFree = 0.05
#Maximum Percentage CPU usage before raising alert
$CPUUsagePercent = 90
#Minimum Percentage Free Memory usage before raising alert
$MemoryFreeUsagePercent = 10
#Comma separated array of network interfaces to be ignored
$IgnoreNetworkFailures = @("Embedded LOM 1 Port 4","Embedded LOM 1 Port 3","Embedded FlexibleLOM 1 Port 2","Embedded FlexibleLOM 1 Port 1")
#Comma separated array of IP addresses to NOT ping (by default GreenScreen will ping all addresses on each server)
$IgnoreIPaddresses = @("11.216.7.4","10.121.139.74")
#Comma separated array of server event numbers to ignore
$IgnoreServerEvents = @("10016")
#Comma separated array of servers to not log disk space
$IgnoreServerDiskSpace = @("server1.domain.net","server2.domain.net","server3.domain.net")
#Comma separated array of servers to not log hardware errors
$IgnoreHardwareErrors = @("server1.domain.net","server2.domain.net","server3.domain.net")
#Services to monitor
$DesiredStateServices = @("GxClMgrS(Instance001)","GxCVD(Instance001)","GXMMM(Instance001)","GxFWD(Instance001)")

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\windows\windows_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\windows\windows_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "Windows Health"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING\Monitor\windowshealth.html"
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
$recipients = "someone@domain.com","someoneelse@domain.com"
#Send email from this address
$fromaddress = "someone-Alerts@domain.com"
#Send email using this relay host
$smtpserver = "smtp.domain.com"

#Credentials
#Credential for IPMI
$IPMICredential = Import-CliXml -Path c:\source\scripts\Credentials\hpeilo.xml
#Credential for Servers
$Credential = Import-CliXml -Path c:\source\scripts\Credentials\serveradmin.xml
