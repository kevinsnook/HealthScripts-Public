#...................................
# Variables
#...................................

#Maxima and minima
$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
$MaxHoursToScanLog = 1                                      #Max hours to go back and alert in logs
$VolumeFullPercentageError = 95                             #Percentage full before Error
$VolumeFullPercentageWarning = 85                           #Percentage full before Warning

#...................................
# PURE controllers
$PUREControllers = "11.111.111.11","22.222.22.2"
#...................................

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\PURE\PURE_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\PURE\PURE_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "PURE Health"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING/Monitor/PUREHealth.html" 
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file (see $ReportFile)
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\PUREHealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$false
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true
#URL of file to output errors report to (this is a separate file for error output from the array)
$ErrorsURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING\Monitor\PUREHealthreporterrors.html"
#Name of file to output errors report to (this is a separate file for error output from the array)
$ErrorsFile = "C:\inetpub\wwwroot\monitor\PUREHealthreporterrors.html"


#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "someone@domain.com"
#Send email from this address
$fromaddress = "someone-ALerts@domain.com"
#Send email using this relay host
$smtpserver = "smtp.domain.com"


#...................................
#Credentials
#....................................

#Monitoring user (RO user setup on PURE clusters)
$PURECredential = Import-CliXml -Path c:\source\scripts\Credentials\pureuser.xml
