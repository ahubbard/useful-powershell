<# 
.DESCRIPTION 
     Name: Delete_Orphaned_Computers_from_AD.ps1 
     Version: 1.0.1
     AUTHOR: ahubbard
     DATE  : 3/13/2017 
      
.SYNOPSIS 
     Checks Active Directory for irregular computer account conditions and optionally removes orphaned entries 
      
.EXAMPLE
     <path>\Delete_Orphaned_Computers_from_AD.ps1
           
.REQUIRES
    Filename: AWScreds.ini: Two AWS Credentials in .ini format, the first with READ permissions, the second with MAIL permissions
    Network: Access to READ S3 encrypted bucket containing AES Key, filename: AD.key
    Filename: ADPass: encrypted (with AD.key) AD Credentials with WRITE permissions

.NOTES
    Sanitizing replaced sensitive information with xxx
#> 

#region Pre-requisites

    # Check if Remote Server Administration Tools are installed on a Windows Server (RSAT). If not, install to provide AD Module
    Import-Module ServerManager
    Get-WindowsFeature RSAT-AD-PowerShell | Add-WindowsFeature | Out-Null
    Import-Module ActiveDirectory

    # Need to preinstall AWS module
    Import-Module AWSPowerShell

#endregion

#region Configurable variables

    #region AWS credentials
        Clear-AWSDefaults
        $CloudProfiles = Get-Content AWScreds.ini
        $CloudReadProfile = $CloudProfiles[0] -replace'[][]',''
        $CloudMailProfile = $CloudProfiles[4] -replace'[][]',''
        # Set default user
        Set-AWSCredentials -AccessKey $CloudProfiles[1].Substring($CloudProfiles[1].LastIndexOf(' ')+1) `
                           -SecretKey $CloudProfiles[2].Substring($CloudProfiles[2].LastIndexOf(' ')+1) `
                           -StoreAs ($CloudProfiles[0] -replace'[][]','')
        Initialize-AWSDefaults -ProfileName $CloudReadProfile
        # Set mail user
        Set-AWSCredentials -AccessKey $CloudProfiles[5].Substring($CloudProfiles[5].LastIndexOf(' ')+1) `
                           -SecretKey $CloudProfiles[6].Substring($CloudProfiles[6].LastIndexOf(' ')+1) `
                           -StoreAs $CloudMailProfile
        [array]::Clear($CloudProfiles, 0, $CloudProfiles.Length)
    #endregion

    #region Secure AD credential
        $ADReadUser = 'xxx\xxx'

        # S3 can't read to memory, so copy the key to local file system, read it to memory, securely wipe memory, remove the file, securely wipe the file, 
        Read-S3Object -BucketName 'xxx' -Key 'AD.key' -File './Key/AD.key' | Out-Null
            [byte[]]$EncryptionKey = Get-Content ./Key/AD.key
            $SecureEncryptionKey = [System.Text.Encoding]::Unicode.GetString($EncryptionKey) | ConvertTo-SecureString -AsPlainText -Force
            [array]::Clear($EncryptionKey, 0, $EncryptionKey.Length)    
        Remove-Item -Recurse ./Key
        Start-Job -ScriptBlock {Cipher /w:./Key} | Out-Null

        $ADReadPassword = Get-Content ADpass | ConvertTo-SecureString -SecureKey $SecureEncryptionKey
        $ADCredential = New-Object -TypeName System.Management.Automation.PSCredential ($ADReadUser,$ADReadPassword)
    #endregion

    #region AD container, domain, AWS region
    $ADOU = '' # format: 'OU=Servers,OU=ExploitCore' *(remember to reverse the order)*
    $ADDomain = Get-ADDomain -Credential $ADCredential  | Select-Object -ExpandProperty DistinguishedName

    If ($ADDomain -eq 'DC=xxx,DC=xxx') {
        $CloudRegion = 'us-west-2'
        $SMTP = 'email-smtp.us-west-2.amazonaws.com'
    }
    Set-DefaultAWSRegion $CloudRegion
    #endregion

    #region Set mail parameters
        $CloudMailUser = (get-awscredentials -ProfileName $CloudMailProfile).GetCredentials().AccessKey
        $CloudMailPassword = (get-awscredentials -ProfileName $CloudMailProfile).GetCredentials().SecretKey | ConvertTo-SecureString -AsPlainText -Force
        $CloudMailCredential = New-Object -TypeName System.Management.Automation.PSCredential $CloudMailUser,$CloudMailPassword
        $MailTo        = 'xxx'
        $MailToAddress = 'xxx@xxx'
        $MailParameters = @{
            Credential = $CloudMailCredential
            SmtpServer = $SMTP
            UseSSL     = $true
            Port       = '587'
            From       = 'noreply@xxx.xxx'
            To         = $MailToAddress
            Subject    = 'Report: Orphaned computers in Active Directory'
            Attachment = '.\Orphans.csv'
        }
    #endregion

#endregion
    
#region Start reporting, set non-configurable variables

    Write-host "`nUsing these parameters: " -NoNewline -ForegroundColor Green; Write-Host "(Open script to edit)" -ForegroundColor Yellow
    Write-Host "`n`t" -NoNewLine; Write-Host "Container:`t`t`t`t`t`t`t" -BackgroundColor Black
    If ($ADOU) {
        $SearchBase = $ADOU +","+ $ADDomain
        Write-Host "`t`t" -NoNewline; Write-Host "$ADOU" -BackgroundColor Black
    }
    Else {
        $SearchBase = $ADDomain
        Write-Host "`t`t" -NoNewline; Write-Host "None specified, using root" -BackgroundColor Black
    }
    Write-Host "`t" -NoNewLine; Write-Host "Domain:`t`t`t`t`t`t`t`t" -BackgroundColor Black
    Write-Host "`t`t" -NoNewline; Write-Host "$($ADDomain -Split ',' -join '.' -replace 'DC=','')" -BackgroundColor Black
    Write-Host "`t" -NoNewLine; Write-Host "Active Directory reader:`t`t`t" -BackgroundColor Black
    Write-Host "`t`t" -NoNewline; Write-Host "$ADReadUser" -BackgroundColor Black
    Write-Host "`t" -NoNewLine; Write-Host "Cloud reader:`t`t`t`t`t`t" -BackgroundColor Black
    Write-Host "`t`t" -NoNewline; Write-Host $CloudReadProfile -BackgroundColor Black
    Write-Host "`t" -NoNewLine; Write-Host "Report will be sent to:`t`t`t`t" -BackgroundColor Black
    Write-Host "`t`t" -NoNewline; Write-Host $MailTo -BackgroundColor Black
    Write-Host "`nDiscovering computers:" -ForegroundColor Green
    
    $ADComputers = @()
    $ADComputersParameters = @{
        Credential = $ADCredential
        SearchBase = $SearchBase
        Filter     = {(PrimaryGroupID -ne 516) -and (Name -notlike "*xxx*")}
    }
    $CloudInfrastructure = @()
    $ADValidCandidates = [ordered]@{}
    $OrphanedADComputers = [ordered]@{}
    $NullIPs = @{}
    $CloudIPs = @{}
    [System.Collections.ArrayList]$DuplicateOrphans = @()
    $DuplicateADComputers = @{}
    $DisabledADComputers = @{}
    $ExpiredADComputers = @{}
    $InactiveADComputers = @{}
    $ExemptComputers = @()
    $ExemptComputerIPs = @()
    $ExemptADLinuxComputers = @()
    $ExemptValidComputers = @{}
    $ExemptOrphans = @()
    $ExemptOrphanedComputers = @{}
    $ExemptADComputers = @{}
    $VacatedIPs = @{}
    $WindowsADComputers = @{}
    $AmazonComputers = @{}
    $OfflineADOrphans = @{}
    $OfflineADCandidates = @{}
    $OfflineADCommentedComputers = @{}
    $OfflineADComputers = @{}
    [ValidateRange(0,4)][int]$ConsistencyCheck = 0
    [ValidateRange(0,5)][int]$InconsistentLists = 0
    $Confirm = 'N'
    $MadLibs = @()
    [System.Text.StringBuilder]$Body = ' '
    $FailedRemovalADComputers = @{}

#endregion

#region Inventory AD computers and cloud infrastructure

    # Populate the list of all valid computers by querying correct Distinquished Name. Ignore Domain Controllers, Bastion hosts, FGMod, and FGMod Citrix
    $ADComputers = Get-ADComputer @ADComputersParameters -Properties AccountExpirationDate,Comment,Created,IPv4Address,LastLogonDate |
        Select-Object AccountExpirationDate,Comment,Created,DistinguishedName,Enabled,IPv4Address,Name,LastLogonDate |
        Sort-Object -Property Created

    Write-Host "`n`tFound " -NoNewLine ; Write-Host $ADComputers.Count -NoNewline -ForegroundColor Red; " computers in Active Directory"
    Write-Host "`t`tExclusions: " -NoNewLine; Write-Host "Domain Controllers, , FGM`n" -ForegroundColor Red

    # Find any IPs in AD that belong to Amazon Elastic IPs, Amazon Elastic Load Balancers (ELB), or Amazon Relational Database Service (RDS) and remove from AD
    "`tQuerying cloud provider:"
    $CloudInfrastructure =  Get-EC2NetworkInterface | Select-Object -Property Description -ExpandProperty PrivateIpAddresses | 

        # Build identifiers for those Amazon Services
        Select-Object Description,@{Name = 'Elastic IP Allocation';Expression = {$_.Association.AllocationId}},@{'Name' = 'PrivateIpAddress';Expression = {$_.PrivateIpAddress}} |

        # Filter the identifiers
        Where {($_.'Elastic IP Allocation' -like 'eipalloc-*' -or $_.description -like 'ELB*' -or $_.description -eq 'RDSNetworkInterface')}

    Write-Host "`n`t`tFound " -NoNewline; Write-Host $CloudInfrastructure.Count -ForegroundColor Red -NoNewline; " infrastructure ips in the cloud provider:"
    Write-Host "`n`t`t`t$(($CloudInfrastructure | Where {$_.'Elastic IP Allocation' -like 'eipalloc-*'}).Count) " -NoNewline -ForegroundColor Red; "Elastic IP(s) with private IP address(es)"
    Write-Host "`t`t`t$(($CloudInfrastructure | Where {$_.Description -like 'ELb*'}).Count) " -NoNewline -ForegroundColor Red; "Elastic Load Balancer(s) (ELB) IP address(es)"
    Write-Host "`t`t`t$(($CloudInfrastructure | Where {$_.Description -eq 'RDSNetworkInterface'}).Count) " -NoNewline -ForegroundColor Red; "Relational Database Services (RDS) IP address(es)"

#endregion

#region Find easy to identify orphans, then build hash table to avoid looping searches for further analysis

    For ($ADComputer = 0 ; $ADComputer -le $ADComputers.Count - 1; $ADComputer++) {
  
        # Check for null addesses in Active Directory. Checks first to avoid having to handle errors later
        If (!($ADComputers[$ADComputer].IPv4Address)) {
            $OrphanedADComputers.Add($ADComputers[$ADComputer].DistinguishedName,  "`$null")
            $NullIPs.Add($ADComputers[$ADComputer].DistinguishedName, "`$null")
        }

        # Check for cloud infrastrcture IPs in Active Directory
        ElseIf ($CloudInfrastructure.PrivateIPAddress -contains $ADComputers[$ADComputer].IPv4Address) {
            $OrphanedADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
            $CloudIPs.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
        }
        
        # Check for duplicate ip's and add older to orphans. Master inventory is sorted by created, earlier is always older
        ElseIf ($ADValidCandidates.Keys -contains $ADComputers[$ADComputer].IPv4Address){
            $DuplicateOrphans = $ADComputers | Where {$_.IPv4Address -eq $ADComputers[$ADComputer].IPv4Address}
            While ($DuplicateOrphans.Count -ge 2) {

                # Check if already added to orphans for another criteria
                If ($OrphanedADComputers.Keys -notcontains $DuplicateOrphans[0].DistinguishedName) {
                    $OrphanedADComputers.Add($DuplicateOrphans[0].DistinguishedName, $DuplicateOrphans[0].IPv4Address)
                    $DuplicateADComputers.Add($DuplicateOrphans[0].DistinguishedName, $DuplicateOrphans[0].IPv4Address)
                }
                $DuplicateOrphans.Remove($DuplicateOrphans[0])
            }
            $ADValidCandidates.Set_Item($DuplicateOrphans.IPv4Address, $DuplicateOrphans.DistinguishedName)
        }

        # Check for disabled computers
        ElseIf (!($ADComputers[$ADComputer].Enabled)) {
            $OrphanedADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
            $DisabledADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
        }

        # Check for expired computers
        ElseIf (!($ADComputers[$ADComputer].AccountExpirationDate -lt (Get-Date).AddDays(-1))) {
            $OrphanedADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
            $ExpiredADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
        }

        # Check for computers that haven't checked in in at least 30 days
        ElseIf ($ADComputers[$ADComputer].LastLogonDate -lt (Get-Date).AddDays(-31)) {
            $OrphanedADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
            $InactiveADComputers.Add($ADComputers[$ADComputer].DistinguishedName, $ADComputers[$ADComputer].IPv4Address)
        }

        # If the ip is still valid at this point add to hash table
        Else {
            $ADValidCandidates.Add($ADComputers[$ADComputer].IPv4Address, $ADComputers[$ADComputer].DistinguishedName)
        }

        # Show progress, but only every-other to limit overhead
        If ($ADComputer % 2) {
            Write-Progress -Activity "Building Active Directory inventory" -Status "% Complete" -PercentComplete ($ADComputer/$ADComputers.Count * 100) -CurrentOperation $ADComputer.Name
        }
    }

    Write-Progress -Activity "Building Active Directory inventory" -Status "Completed" -Completed
    Write-Host "`n`tFound " -NoNewLine  -ForegroundColor Yellow; Write-Host $CloudIPs.Count -NoNewline -ForegroundColor Red; Write-Host " cloud infrastructure ip(s) in Active Directory"  -ForegroundColor Yellow

#endregion

#region Find and remove exempt computers from consideration

    Write-Host "`nFinding exempt computers :" -ForegroundColor Green

    # Find Linux computers properly added to Active Directory (currently denoted by lowercase) and match $ExemptComputers format
    "`n`tQuerying Active Directory:"
    $ExemptADLinuxComputers = $ADComputers |
        Where {$_.Name -ceq ($_.Name).ToLower()} |
        Select-Object @{Name = 'PrivateIPAddress';Expression = {$_.IPv4Address}}
    Write-Host "`n`t`tFound " -NoNewline; Write-Host $ExemptADLinuxComputers.Count -NoNewline -ForegroundColor Red; " exempt computer(s) in Active Directory"

    "`n`tQuerying cloud provider:"
    
    # Get non-terminated, not-pending instance, properties
    $ExemptComputers = (((Get-EC2instance -Filter @{Name = 'instance-state-code'; Value = '16','32','64','80'}).Instances)) |
        
        #Get private ip(s) for the AWS tagged names
        Select-Object PrivateIPAddress, @{Name = "Name"; Expression = {$_.Tags | Where Key -eq "Name" | Select-Object -ExpandProperty Value }} |
    
        # Exempt "Do Not Delete" and xxx
        Where {$_.Name -like '*t?delete*' -or $_.Name -like '*xxx*'}

    Write-Host "`n`t`tFound " -NoNewline; Write-Host $ExemptComputers.Count -NoNewline -ForegroundColor Red; " additional exempt computer(s) in the cloud provider"
    
    # De-dupe
    $ExemptComputerIPs = (Compare-Object $ExemptComputers.PrivateIPAddress $ExemptADLinuxComputers.PrivateIPAddress -IncludeEqual).InputObject

    # Check for exempt computers and remove from further consideration
    Foreach ($ExemptComputerIP in $ExemptComputerIPs) {
        If ($ADValidCandidates[$ExemptComputerIP] -ne $null) {
            $ExemptValidComputers.Add($ADValidCandidates[$ExemptComputerIP], $ExemptComputerIP)
            $ADValidCandidates.Remove($ExemptComputerIP)
        }
        
        # Note: only removes from orphans, not subcategory lists like $NullIPs. Also has caught duplicate IPs, so Count-1
        ElseIf ($OrphanedADComputers.GetEnumerator() | Where {$_.Value -eq $ExemptComputerIP} | Tee-Object -Variable ExemptOrphans) {
            $ExemptOrphanedComputers.Add($ExemptOrphans[$ExemptOrphans.Count-1].Name, $ExemptComputerIP)
            $OrphanedADComputers.Remove($ExemptOrphans[$ExemptOrphans.Count-1].Name)
        }
    }
    $ExemptADComputers = $ExemptValidComputers + $ExemptOrphanedComputers

#endregion

#region Interim reporting

    Write-Host "`n`tFound " -NoNewLine  -ForegroundColor Yellow; Write-Host $ExemptADComputers.Count -NoNewline -ForegroundColor Red; Write-Host " total exempt computer(s) in Active Directory:"  -ForegroundColor Yellow
    Write-Host "`n`t`tFound " -NoNewLine; Write-Host $ExemptOrphanedComputers.Count -NoNewline -ForegroundColor Red; Write-Host " exempt computer(s) identified as an orphaned computer"    
    Write-Host "`t`tFound " -NoNewLine; Write-Host $ExemptValidComputers.Count -NoNewline -ForegroundColor Red; Write-Host " computer(s) to add to exemptions"
    Write-Host "`nFound " -NoNewLine -ForegroundColor Green; Write-Host $OrphanedADComputers.Count -NoNewline -ForegroundColor Red; Write-Host " orphaned computer(s) in Active Directory:" -ForegroundColor Green
    Write-Host "`n`tFound " -NoNewLine; Write-Host $NullIPs.Count -NoNewline -ForegroundColor Red; " computer(s) with no IP address"
    Write-Host "`tFound " -NoNewLine; Write-Host $DuplicateADComputers.Count -NoNewline -ForegroundColor Red; " computer(s) with duplicate IP addresses"
    Write-Host "`tFound " -NoNewLine; Write-Host $DisabledADComputers.Count -NoNewline -ForegroundColor Red; " disabled computer(s)"
    Write-Host "`tFound " -NoNewLine; Write-Host $ExpiredADComputers.Count -NoNewline -ForegroundColor Red; " expired computer account(s)"
    Write-Host "`tFound " -NoNewLine; Write-Host $InactiveADComputers.Count -NoNewline -ForegroundColor Red; " inactive computer(s)"

#endregion

#region Find remaining orphaned computers

    # Ping to determine online state
    Write-Host "`nConducting network tests on " -NoNewline -ForegroundColor Green; Write-Host $ADValidCandidates.Count -NoNewline -ForegroundColor Red; Write-Host " remaining computer(s):" -ForegroundColor Green

    Workflow Test-NetworkConnection {

        param (
            [string[]]$Computers
        )

        ForEach -Parallel -ThrottleLimit 50 ($Computer in $Computers) {
            Test-Connection -ComputerName $Computer -Count 1 -ErrorAction SilentlyContinue | Select-Object -Property Address,ResponseTimeToLive
        }
    }

    $OnlineADComputers = Test-NetworkConnection -Computers $ADValidCandidates.Keys | Select-Object -Property Address,ResponseTimeToLive
    
    # Check online computers for validity by checking the OS
    ForEach ($OnlineADComputer in $OnlineADComputers) {

        Switch($OnlineADComputer) { 
            
            # If a linux computer has not been added to AD, and is merely using the same ip address of an entry, add to orphans
            {$_.ResponseTimeToLive -eq 64} {
                $OrphanedADComputers.Add($ADValidCandidates.Item($OnlineADComputer.Address), $OnlineADComputer.Address)
                $VacatedIPs.Add($ADValidCandidates.Item($OnlineADComputer.Address), $OnlineADComputer.Address)
                break
            }
            
            # If a windows computer is online, do nothing but report
            {$_.ResponseTimeToLive -eq 128} {
                $WindowsADComputers.Add($ADValidCandidates.Item($OnlineADComputer.Address), $OnlineADComputer.Address)
                break
            }
            
            # If Amazon infrastructure is using the same ip address of an entry, add to orphans
            {$_.ResponseTimeToLive -eq 255} {
                $AmazonComputers.Add($ADValidCandidates.Item($OnlineADComputer.Address), $OnlineADComputer.Address)
                $OrphanedADComputers.Add($ADValidCandidates.Item($OnlineADComputer.Address), $OnlineADComputer.Address)
                break
            }
        }
  
        $ADValidCandidates.Remove($OnlineADComputer.Address)
    }

    Write-Host "`n`tFound " -NoNewLine; Write-Host $OnlineADComputers.Count -NoNewline -ForegroundColor Red; " IP(s) online in Active Directory:"
    Write-Host "`n`t`tFound " -NoNewLine; Write-Host $VacatedIPs.Count -NoNewline -ForegroundColor Red; " vacated IP address(es) in Active Directory"
    Write-Host "`t`tFound " -NoNewLine; Write-Host $WindowsADComputers.Count -NoNewline -ForegroundColor Red; " with valid computer accounts"
    Write-Host "`t`tFound " -NoNewLine; Write-Host $AmazonComputers.Count -NoNewline -ForegroundColor Red; " orphaned Amazon infrastructure IP(s) previously unaccounted for"
    Write-Host "`n`tChecking " -NoNewLine; Write-Host $ADValidCandidates.Count -NoNewline -ForegroundColor Red; " computer(s) currently offline:"

    # Evaluate offline computers
    Foreach ($ADValidCandidate in 0..($ADValidCandidates.Count -1)) {

        $OfflineADComputers.Add($ADValidCandidates[0], $ADValidCandidateComputer.IPv4Address)
        $ADValidCandidateComputer = $ADComputers |
            Where {$_.DistinguishedName -eq $ADValidCandidates[0]} |
            Select-Object Comment,IPv4Address

        # If offline, see if there's a comment
        If ($ADValidCandidateComputer.Comment -ne $null) {

            # If there's a comment check if the comment gave an offline date
            If ($ADValidCandidateComputer.Comment | Where {$_ -like 'Offline <= *'}) {

                # If so, do nothing but report if the date was within the past 7 days
                If ([datetime]($ADValidCandidateComputer.Comment -split '<= ')[1] -ge (get-date).AddDays(-7)) {
                    $OfflineADCandidates.Add($ADValidCandidates[0], $ADValidCandidateComputer.IPv4Address)
                }
                        
                # If it's been more than 7 day, add to orphans
                Else {
                $OfflineADOrphans.Add($ADValidCandidates[0], $ADValidCandidateComputer.IPv4Address)
                $OrphanedADComputers.Add($ADValidCandidates[0], $ADValidCandidateComputer.IPv4Address)
                $OfflineADComputers.Remove($ADValidCandidates[0])
                }
            }
        }

        # If there's no previous comment, add one dated today
        Else {
            Set-ADComputer -Credential $ADCredential $ADValidCandidates[0] -Replace @{comment = "Offline <= " + (Get-Date -format d)}
            $OfflineADCommentedComputers.Add($ADValidCandidates[0], $ADValidCandidateComputer.IPv4Address)
        }

        Write-Progress -Activity "Checking offline computers" -Status "% Complete" `
            -PercentComplete ($ADValidCandidate / ($ADValidCandidates.Count + $OfflineADComputers.Count + $OrphanedADComputers.Count) * 100)
         
        $ADValidCandidates.Remove($ADValidCandidateComputer.IPv4Address)
    }

    Write-Progress -Activity "Checking offline computers" -Status "Completed" -Completed
    Write-Host "`n`t`tFound " -NoNewLine; Write-Host $OfflineADCommentedComputers.Count -NoNewline -ForegroundColor Red; " computer(s) offline for the first time and flagged"
    Write-Host "`t`tFound " -NoNewLine; Write-Host $OfflineADCandidates.Count -NoNewline -ForegroundColor Red; " computer(s) offline less than a week, continuing to monitor"
    Write-Host "`t`tFound " -NoNewLine; Write-Host $OfflineADOrphans.Count -NoNewline -ForegroundColor Red; " computer(s) that have been offline more than a week and orphaned"

#endregion

#region Sanity checks

    Write-Host "`nConducting consistency checks on " -NoNewline -ForegroundColor Green; Write-Host $OrphanedADComputers.Count -NoNewline -ForegroundColor Red; Write-Host " orphaned computer(s):" -ForegroundColor Green

    If ($OrphanedADComputers.Count -eq ($NullIPs.Count + $CloudIPs.Count + $DuplicateADComputers.Count + $DisabledADComputers.Count + $ExpiredADComputers.Count + $InactiveADComputers.Count - $ExemptOrphanedComputers.Count + $VacatedIPs.Count + $OfflineADOrphans.Count)) {
        Write-Host "`n`tDeduplication confirms " -NoNewline -ForegroundColor Yellow; Write-Host $OrphanedADComputers.Count -NoNewline -ForegroundColor Red; Write-Host " orphaned computer entries" -ForegroundColor Yellow
        $ConsistencyCheck++
    }
    Else {
        Write-Host "`n`tOrphaned inconsistent. Check exceptions" -BackgroundColor DarkRed -ForegroundColor Red
    }
    
    $RemainingADComputers = Compare-Object ($ADComputers | Select-Object -ExpandProperty DistinguishedName) ($OrphanedADComputers | Select-Object -ExpandProperty Keys)

    If ((($OfflineADComputers.Count + $WindowsADComputers.Count) + $ExemptADComputers.Count + $ADValidCandidates.Count) -eq $RemainingADComputers.Count) {
        Write-Host "`tRemaining non-orphans are " -NoNewline; Write-Host "correct:" -NoNewline -BackgroundColor DarkGreen -ForegroundColor Green; Write-Host " $($RemainingADComputers.Count)" -ForegroundColor Red
        $ConsistencyCheck++
    }
    Else {
        Write-Host "`tRemaining non-orphans inconsistent. Check exceptions" -BackgroundColor DarkRed -ForegroundColor Red
    }

        # Check for inconsistent lists
        $RemainingADComputers = Compare-Object ($OfflineADComputers | Select-Object -ExpandProperty Keys) ($OnlineADComputers | Select-Object -ExpandProperty Address) -ExcludeDifferent
        If ($RemainingADComputers.Count -eq 0) {
            $InconsistentLists++
        }
        Else {
            Write-Host "`tOverlap exists between Offline and Online computers" -BackgroundColor DarkRed -ForegroundColor Red
        }

        $RemainingADComputers = Compare-Object ($OfflineADComputers | Select-Object -ExpandProperty Keys) ($OrphanedADComputers | Select-Object -ExpandProperty Keys) -ExcludeDifferent
        If ($RemainingADComputers.Count -eq 0) {
            $InconsistentLists++
        }
        Else {
            Write-Host "`tOverlap exists between Orphaned, Remaining!" -BackgroundColor DarkRed -ForegroundColor Red
        }

        # Ensure computers were properly exempted
        $RemainingADComputers = Compare-Object ($OfflineADComputers | Select-Object -ExpandProperty Keys) ($ExemptADComputers | Select-Object -ExpandProperty Keys) -ExcludeDifferent
        If ($RemainingADComputers.Count -eq 0) {
            $InconsistentLists++
        }
        Else {
            Write-Host "`tOverlap exists between Remaining, Exempt!"  -BackgroundColor DarkRed -ForegroundColor Red
        }
    
        $RemainingADComputers = Compare-Object ($OrphanedADComputers | Select-Object -ExpandProperty Keys) ($ExemptADComputers | Select-Object -ExpandProperty Keys) -ExcludeDifferent
        If ($RemainingADComputers.Count -eq 0) {
            $InconsistentLists++
        }
        Else {
            Write-Host "`tOverlap exists between Orphaned, Exempt!"  -BackgroundColor DarkRed -ForegroundColor Red
        }

        If ($InconsistentLists = 4) {
            Write-Host "`t" -NoNewline; Write-Host "No overlap" -NoNewline -BackgroundColor DarkGreen -ForegroundColor Green; Write-Host " " -NoNewline; Write-Host "between Remaining, Online, Offline, Orphaned, Exempt"
            $ConsistencyCheck++
        }

        $RemainingADComputers = Compare-Object ($WindowsADComputers | Select-Object -ExpandProperty Keys) ($OrphanedADComputers | Select-Object -ExpandProperty Keys) -ExcludeDifferent
        If ($RemainingADComputers.Count -eq 0) {
            $InconsistentLists++
        }
        Else {
            Write-Host "`tA valid computer has incorrectly been identified as an ophan! Check exceptions."  -BackgroundColor DarkRed -ForegroundColor Red
        }

    # Check for catastropic failures. Would be related to Active Directory or Cloud Provider
    If ($ADComputers.Count -eq 0 -or $CloudIPs.Count -eq 0) {
        $ConsistencyCheck = 0
    }

    If (($ADComputers.Count -eq (($OfflineADComputers.Count + $WindowsADComputers.Count) + $ExemptADComputers.Count + $OrphanedADComputers.Count)) -and ($ConsistencyCheck -gt 0)) {
            Write-Host "`n`tProcessed all " -NoNewline -ForegroundColor Green; Write-Host $ADComputers.Count -NoNewline; Write-Host " " -NoNewLine; Write-Host "successfully!" -BackgroundColor DarkGreen -ForegroundColor Green
            $ConsistencyCheck++
    }
    Else {
        Write-Host "`nProcessing inconsistent! Check exceptions." -BackgroundColor DarkRed -ForegroundColor Red
    }

#endregion

#region Reporting and prompt for action. If removing, check for AD recycle bin.

    If ($InconsistentLists -eq 5 -and $ConsistencyCheck -eq 4) {

        $OrphanedADComputers | Format-Wide  -Column 8 -Property @{Expression={$_.Key.Split(',')[0] -replace 'CN=',''}}

        Write-Host "`nRemove these " -NoNewLine -ForegroundColor Yellow; Write-Host $OrphanedADComputers.Count -NoNewLine -ForegroundColor Red; Write-Host " computers? " -NoNewline -ForegroundColor Yellow
        $Confirm = Read-Host -Prompt "(Y)es (N)o"
         
        If ($Confirm.ToLower() -eq "y") {
            If ((Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}).EnabledScopes -ne $null) {
                Write-Host "Confirmed Active Directory Recycle Bin is " -NoNewline; Write-Host "Enabled" -NoNewline -BackgroundColor DarkGreen -ForegroundColor Green; "!"
            }

            Else {
                Write-Host "Active Directory Recycle Bin is " -NoNewLine; Write-Host "Disabled" -NoNewLine -BackgroundColor DarkRed -ForegroundColor Red
                $Confirm = Read-Host -Prompt ". Enable? (Y)es (N)o"

                If ($Confirm.ToLower() -eq "y") {
                    $Identity = 'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' + $ADDomain
                    Enable-ADOptionalFeature -Credential $ADCredential -Identity $Identity -Scope ForestOrConfigurationSet -Target ($ADDomain -split ',' -join '.' -replace 'DC=','')

                    If ((Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"}).EnabledScopes -ne $null) {
                        Write-Host "Active Directory Recycle Bin is " -NoNewline; Write-Host "Enabled" -NoNewline -BackgroundColor DarkGreen -ForegroundColor Green; "!"
                    }
                    Else {
                        Write-Host "Enabling Active Directory Recycle Bin " -NoNewLine; Write-Host "Failed" -NoNewLine -BackgroundColor DarkRed -ForegroundColor Red; "!"
                        $Confirm = Read-Host -Prompt "Continue removal? (Y)es (N)o"
                    }
                }
            }

            If ($Confirm.ToLower() -eq "y") {
                ForEach ($OrphanedADComputer in $OrphanedADComputers.GetEnumerator()) {
                    Remove-ADComputer -Credential $ADCredential $OrphanedADComputer.Key -Confirm:$false
                }
            }
        }
    }

#endregion

#region Confirm or deny success and final report

    $MadLibs =  @('Completed';'Removed ';'Identified ';'Monitoring ';'Found ')
            $MadLibs += @(' ';'successfully';'. ';'NO';' further action taken.';'All orphans not successfully removed!';'Unable to remove ')
            $MadLibs += @('!';' computer(s)';': ';' orphaned computer(s) in Active Directory.';' valid';'.')
    
     If ($Confirm.ToLower() -eq "y") {
         $ADComputers = Get-ADComputer @ADComputersParameters |Select-Object -ExpandProperty DistinguishedName

        $RemainingADComputers = (Compare-Object $ADComputers ($OrphanedADComputers | Select-Object -ExpandProperty Keys) -IncludeEqual -ExcludeDifferent).InputObject
        If ($RemainingADComputers.Count -eq 0) {
            Write-Host "`n" -NoNewLine; Write-Host $MadLibs[0] -NoNewline; Write-Host $MadLibs[5] -NoNewline; Write-Host $MadLibs[6] -NoNewline -BackgroundColor DarkGreen -ForegroundColor Green; Write-Host $MadLibs[12]
            $Body.Append($MadLibs[0] + $MadLibs[5] + $MadLibs[6] + $MadLibs[12] + "`r`n`t") | Out-Null
            Write-Host "`n`t" -NoNewLine; Write-Host $MadLibs[1] -NoNewline; Write-Host $OrphanedADComputers.Count -NoNewline -ForegroundColor Red; Write-Host $MadLibs[15]
            $Body.Append($MadLibs[1] + $OrphanedADComputers.Count + $MadLibs[15] + "`r`t") | Out-Null
        }

        Else {
            Write-Host "`n" -NoNewLine; Write-Host $MadLibs[10] -ForegroundColor Red -BackgroundColor DarkRed
            $Body.Append($MadLibs[10] + "`r`n`t") | Out-Null
            Write-Host "`t" -NoNewLine; Write-Host $MadLibs[11] -NoNewLine -ForegroundColor Red; Write-Host $RemainingADComputers.Count -NoNewline -ForegroundColor Red; Write-Host $MadLibs[13] -NoNewLine -ForegroundColor Red; $MadLibs[14]
            $Body.Append($MadLibs[11] + $RemainingADComputers.Count + $MadLibs[13] + $MadLibs[14] + "`r`t") | Out-Null
            $RemainingADComputers | Format-Wide  -Column 8 -Property @{Expression={$_.Split(',')[0] -replace 'CN=',''}} -Force
            Foreach ($RemainingADComputer in $RemainingADComputers) {
                If ($OrphanedADComputers[$RemainingADComputer] -ne $null) {
                    $FailedRemovalADComputers.Add($RemainingADComputer, $OrphanedADComputers[$RemainingADComputer])
                }
            }
            $FailedRemovalADComputers.GetEnumerator() | Select-Object Name,Value | Export-Csv FailedRemoval.csv -NoTypeInformation
            [string[]]$MailParameters.Attachment = $MailParameters.Attachment,'.\FailedRemoval.csv'
        }
    }

    Else {
        Write-Host "`n" -NoNewLine; Write-Host $MadLibs[0] -NoNewLine; Write-Host $MadLibs[7] -NoNewLine; Write-Host $MadLibs[8] -NoNewline -BackgroundColor DarkRed -ForegroundColor Red; $MadLibs[9]
        $Body.Append($MadLibs[0] + $MadLibs[7] + $MadLibs[8] + $MadLibs[9] + "`r`n`t") | Out-Null
        Write-Host "`n`t" -NoNewLine; Write-Host $MadLibs[2] -NoNewLine; Write-Host $OrphanedADComputers.Count -NoNewline  -ForegroundColor Red; $MadLibs[15]
        $Body.Append($MadLibs[2] + $OrphanedADComputers.Count + $MadLibs[15] + "`r`t") | Out-Null
    }

    Write-Host "`t" -NoNewLine; Write-Host $MadLibs[3] -NoNewLine; Write-Host $OfflineADComputers.Count -NoNewline  -ForegroundColor Yellow; $MadLibs[13] + $MadLibs[17]
    $Body.Append("`t" + $MadLibs[3] + $OfflineADComputers.Count + $MadLibs[13] + $MadLibs[17] + "`r`t") | Out-Null
    Write-Host "`t" -NoNewLine; Write-Host $MadLibs[4] -NoNewLine;  Write-Host $WindowsADComputers.Count -NoNewline  -ForegroundColor Green; $MadLibs[16] + $MadLibs[13] + $MadLibs[17]; "`n"
    $Body.Append("`t" + $MadLibs[4] + $WindowsADComputers.Count + $MadLibs[16] + $MadLibs[13] + $MadLibs[17] + "`r`n") | Out-Null

    $OrphanedADComputers.GetEnumerator() | Select-Object Name,Value | Export-Csv Orphans.csv -NoTypeInformation
    $Body.Append("`nThe list of orphans is attached. `r`n") | Out-Null
    Send-MailMessage @MailParameters -Body $Body.ToString()
    Remove-Item .\Orphans.csv,.\FailedRemoval.csv

#endregion