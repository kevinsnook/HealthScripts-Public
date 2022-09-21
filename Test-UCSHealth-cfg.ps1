#...................................
# Variables
#...................................

#Max hours to go back and alert in logs
$MaxHoursToScanLog = 24                                     
#Warn if uptime is below this number of hours
$MinimumUptime = 2  

$UCSMServers =  @(“10.251.234.36”)

#Comma seperated array of servids to ignore in the form chassis-1/blade-1@NHC0-NET-FIC001 for blades or rack-unit-1@NHC0-NET-FIC001 for rack servers
#$IgnoreServerIDs = @("rack-unit-6@NHC0-NET-FIC001")

#Comma seperated array of objects to ignore (this will ignore any errors containing the relevant text) (remember the * character)
$IgnoreObjects = @("*NHC0-INF-VDI010*","*testing*","*another*")

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\Cisco\UCS\UCS_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\Cisco\UCS\UCS_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "UCS Health (UK HoldCo)"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://NHC0-EUD-VMAN01/Monitor/UCSHealth.html" 
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file described in $ReportFile
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\UCSHealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$true
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true


#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "ITS.DCI.Datacentre.Services@cobham.com"
#Send email from this address
$fromaddress = "HoldCo-UCS-Alerts@cobham.com"
#Send email using this relay host
$smtpserver = "smtp.eu.cobham.net"

#...................................
# Credentials
#...................................
#UCSM credentials
$UCSCredential = Import-CliXml -Path c:\source\scripts\Credentials\SVC-VMVRRW-001\ciscoadmin.xml



