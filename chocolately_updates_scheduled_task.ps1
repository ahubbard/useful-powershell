<#
.DESCRIPTION
     Name: chocolately_updates_scheduled_task.ps1
     Version: 1.0
     AUTHOR: ahubbard
     DATE  : 5/3/2017

.SYNOPSIS
     Creates a scheduled task to update chocolately packages

.EXAMPLE
     <path>\chocolately_updates_scheduled_task.ps1

.NOTES
    Choco already properly set up
#>

# Settings for the scheduled task
$TaskAction = New-ScheduledTaskAction -Execute 'choco' -Argument 'upgrade all -y'
$TaskTriggers = New-ScheduledTaskTrigger -Daily -At 23:00
$TaskUserPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM'
$TaskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable

$Task = New-ScheduledTask -Action $TaskAction -Principal $TaskUserPrincipal -Trigger $TaskTriggers -Settings $TaskSettings
Register-ScheduledTask -TaskName 'Chocolately upgrade all nightly' -InputObject $Task -Force