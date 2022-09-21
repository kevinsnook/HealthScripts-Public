#...................................
# Variables
#...................................

#Max hours to go back and alert in logs
$MaxHoursToScanLog = 24                                     
#Warn if uptime is below this number of hours
$MinimumUptime = 2  

$UCSMServers =  @(“10.253.234.45","10.243.24.45")

#Comma seperated array of servids to ignore in the form chassis-1/blade-1@FICNAME for blades or rack-unit-1@FICNAME for rack servers
$IgnoreServerIDs = @("rack-unit-6@FICNAME")

#Comma seperated array of objects to ignore (this will ignore any errors containing the relevant text) (remember the * character)
$IgnoreObjects = @("*sometext*","*testing*","*another*")

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\Cisco\UCS\UCS_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\Cisco\UCS\UCS_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "UCS Health"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING/Monitor/UCSHealth.html" 
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
$recipients = "someone@domain.com"
#Send email from this address
$fromaddress = "someone-Alerts@domain.com"
#Send email using this relay host
$smtpserver = "smtp.domain.com"

#...................................
# Credentials
#...................................
#UCSM credentials
$UCSCredential = Import-CliXml -Path c:\source\scripts\Credentials\ciscoadmin.xml



