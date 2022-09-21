#...................................
# Variables
#...................................

#Maxima and minima
$MaxMinutesSinceSnapshot = 60                               #Max minutes since last snapshot
$MaxMinutesSnapMirrorLag = 60                               #Max minutes lag for snapmirrors
$MaxHoursToScanLog =  2                                     #Max hours to go back and alert in logs
$VolumeFullPercentageError = 95                             #Percentage full before Error
$VolumeFullPercentageWarning = 85                           #Percentage full before Warning
$VolumeSnapReserveFullPercentageError = 95                  #Percentage full before Error on snap reserve
$AggregateFullPercentageError = 95                          #Percentage full before Error
$AggregateFullPercentageWarning = 85                        #Percentage full before Warning

#The management IPs of the controllers that you want to monitor
$NetAppControllers = "11.111.1.111","22.222.2.22"

#Report settings
#Determines whether the script logs it's activities using logfile described below
$Log = $true
#Location of log file for script
$logfile = "C:\Source\Scripts\netapp\netapp_health.log"
#Location of transcript file for script (shows command line output for script
$TranscriptFile = "C:\Source\Scripts\netapp\netapp_health_transcript.log"
#Reportsubject = the heading for the html report
$reportsubject = "NetApp Health"
#Enter the URL of the report for use from the Web (this is the URL of the webpage this report will output)
$ReportURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING\Monitor\netapphealth.html"
#ReportMode - Set to $true to generate a HTML report. Uses the name of the Report file (see below)
$ReportMode=$true
#ReportFile - name of file to output html report to
$ReportFile="C:\inetpub\wwwroot\monitor\netapphealth.html"
#Determines whether we send the HTML report via email using the SMTP configuration within the config file.
$SendEmail=$true
#Only sends the email report if at least one error or warning was detected.
$AlertsOnly=$true
#URL of file to output errors report to (this is a separate file for error output from the array)
$ErrorsURL = "http://SERVER_WHERE_SCRIPT_IS_RUNNING\Monitor\netappreporterrors.html"
#Name of file to output errors report to (this is a separate file for error output from the array)
$ErrorsFile="C:\inetpub\wwwroot\monitor\netappreporterrors.html"


#...................................
# Email Settings
#...................................

#Send email to this address
$recipients = "someone@doamin.com"
#Send email from this address
$fromaddress = "fromaddress-Alerts@domain.com"
#Send email using this relay host
$smtpserver = "smtp.domain.com"


#...................................
# Credentials
#...................................

#Login to monitoring user (RO user "monitoring-user" setup on NetApp clusters)
$NetAppCredential = Import-CliXml -Path c:\source\scripts\Credentials\netapp-monitoring-user.xml
