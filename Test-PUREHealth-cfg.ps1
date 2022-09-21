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
$PUREControllers = "10.251.238.40"
#...................................

#Report settings
#Determines whether the script logs it's activities using logfile described in $logfile
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\PURE\PURE_health.log"
#Location of transcript file for script (shows command line output for script)
$TranscriptFile = "C:\Source\Scripts\PURE\PURE_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "PURE Health (UK HoldCo)"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://NHC0-EUD-VMAN01/Monitor/PUREHealth.html" 
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file (see $ReportFile)
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\PUREHealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$false
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true
#URL of file to output errors report to (this is a separate file for error output from the array)
$ErrorsURL = "http://NHC0-EUD-VMAN01\Monitor\PUREHealthreporterrors.html"
#Name of file to output errors report to (this is a separate file for error output from the array)
$ErrorsFile = "C:\inetpub\wwwroot\monitor\PUREHealthreporterrors.html"


#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "ITS.DCI.Datacentre.Services@cobham.com"
#Send email from this address
$fromaddress = "HoldCo-PURE-Alerts@cobham.com"
#Send email using this relay host
$smtpserver = "smtp.eu.cobham.net"


#...................................
#Credentials
#....................................

#Monitoring user (RO user setup on PURE clusters)
$PURECredential = Import-CliXml -Path c:\source\scripts\Credentials\SVC-VMVRRW-001\pureuser.xml
