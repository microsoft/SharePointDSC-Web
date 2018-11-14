Configuration SharePointOAConfig
{
    param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential] 
        $FarmAccount = (Get-Credential -Message "FARM - SharePoint Farm Account"),
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $SPSetupAccount = (Get-Credential -Message "SETUP - Main installer Account"),
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $WebPoolManagedAccount = (Get-Credential -Message "WEB APPS - Web Application Pool Account"),
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $ServicePoolManagedAccount = (Get-Credential -Message "SERVICE APPS - Service Application Pool Account"),
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $DefaultContentAccessAccount = (Get-Credential -Message "CRAWL - Default Crawl Account"),
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $FarmPassPhrase = (Get-Credential -Message "PASSPHRASE - enter the passphrase in the password box, the username is ignored")
    )

    Import-DscResource -ModuleName "SharePointDsc" -ModuleVersion "2.2.0.0"
    Import-DscResource -ModuleName "xWebAdministration" -ModuleVersion "1.19.0.0"
    Import-DscResource -ModuleName "xCredSSP" -ModuleVersion "1.3.0.0"

    $DscStudio = $ConfigurationData.NonNodeData.DscStudio

    $AllNodes.NodeName | Where-Object -FilterScript { 
        $_.NodeName -ne "*"
    } | ForEach-Object -Process {
        if ($_.Contains(".") -eq $false) 
        {
            throw ("The SharePoint Onboarding Accelerator configuration requires that Fully " + `
                   "Qualified Domain Names (FQDNs) are used for computer names. Please modify " + `
                   "the configuration to add the domain name to each node and re-run this " + `
                   "command")
        }
    }

    node $AllNodes.NodeName
    {
        switch ($node.ServerRole)
        {
            "Application Server" {
                $OAServerRole = "Application"
                $MinRole = "Application"
            }
            "Application Server with Search" {
                $OAServerRole = "ApplicationWithSearch"
                $MinRole = "ApplicationWithSearch"
            }
            "Custom" {
                $OAServerRole = "Custom"
                $MinRole = "Custom"
            }
            "Distributed Cache" {
                $OAServerRole = "DistributedCache"
                $MinRole = "DistributedCache"
            }
            "Search" {
                $OAServerRole = "Search"
                $MinRole = "Search"
            }
            "Single Server Farm" {
                $OAServerRole = "SingleServerFarm"
                $MinRole = "SingleServerFarm"
            }
            "Web Front End" {
                $OAServerRole = "WebFrontEnd"
                $MinRole = "WebFrontEnd"
            }
            "Web Front End with Distributed Cache" {
                $OAServerRole = "WebFrontEndWithDistributedCache"
                $MinRole = "WebFrontEndWithDistributedCache"
            }
            default {

            }
        }
        $potentialFarmServers = $AllNodes | Where-Object -FilterScript {
            $_.ServerRole -eq "Single Server Farm" `
            -or $_.ServerRole -eq "Application Server" `
            -or $_.ServerRole -eq "Application Server with Search"
        }
        $FarmServer = $potentialFarmServers.NodeName | Sort-Object | Select-Object -First 1

        if ($null -eq $FarmServer)
        {
            throw ("No server with role 'Application Server' or 'Application Server with Search' " + `
                   "was found. Please add at least one node of this role and re-run the " + `
                   "configuration")
        }
        
        File BinaryCopy 
        {
            SourcePath           = $DscStudio.NetworkBinaries
            DestinationPath      = $DscStudio.LocalBinaries
            PsDscRunAsCredential = $SPSetupAccount
            Ensure               = "Present"
            Type                 = "Directory"
            Recurse              = $true
            MatchSource          = $false 
        }

        #************************************************************
        # Prerequisite Installation
        #
        # This section of the configuration handles the installation
        # of the prereqs. If it's online we just run it and let it 
        # go, but if its offline we define the parameters per version
        #************************************************************ 
        $binaryPath = $DscStudio.LocalBinaries.TrimEnd('\')
        if ($DscStudio.DownloadPrereqs -eq $false) 
        {
            switch ($DscStudio.ProductVersion) 
            {
                "2013" {
                    SPInstallPrereqs InstallPreReqs 
                    {
                        PsDscRunAsCredential = $SPSetupAccount
                        InstallerPath        = "$binaryPath\SharePoint\Prerequisiteinstaller.exe"
                        OnlineMode           = $false
                        Ensure               = "Present"
                        SQLNCli              = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\sqlncli.msi"
                        PowerShell           = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\Windows6.1-KB2506143-x64.msu"
                        NETFX                = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\dotnetfx45_full_x86_x64.exe"
                        IDFX                 = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu"
                        Sync                 = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\Synchronization.msi"
                        AppFabric            = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe"
                        IDFX11               = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi"
                        MSIPCClient          = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\setup_msipc_x64.msi"
                        WCFDataServices      = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\WcfDataServices.exe"
                        KB2671763            = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\AppFabric1.1-RTM-KB2671763-x64-ENU.exe"
                        WCFDataServices56    = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\WcfDataServices56.exe"
                    }
                }
                "2016" {
                    SPInstallPrereqs InstallPreReqs 
                    {
                        PsDscRunAsCredential = $SPSetupAccount
                        InstallerPath        = "$binaryPath\SharePoint\Prerequisiteinstaller.exe"
                        OnlineMode           = $false
                        Ensure               = "Present"
                        SQLNCli              = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\sqlncli.msi"
                        Sync                 = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\Synchronization.msi"
                        AppFabric            = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe"
                        IDFX11               = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi"
                        MSIPCClient          = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\setup_msipc_x64.exe"
                        WCFDataServices56    = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\WcfDataServices.exe"
                        MSVCRT11             = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\vcredist_x64.exe"
                        MSVCRT14             = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\vc_redist.x64.exe"
                        ODBC                 = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\msodbcsql.msi"
                        DotNetFx             = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\NDP46-KB3045557-x86-x64-AllOS-ENU.exe"
                        KB3092423            = "$binaryPath\SharePoint\PrerequisiteInstallerFiles\AppFabric-KB3092423-x64-ENU.exe"
                    }
                }
            }
        } 
        else 
        {
            SPInstallPrereqs InstallPreReqs 
            {
                PsDscRunAsCredential = $SPSetupAccount
                InstallerPath        = "$binaryPath\SharePoint\Prerequisiteinstaller.exe"
                OnlineMode           = $true
                Ensure               = "Present"
            }
        }
        
        #************************************************************
        # SharePoint Installation
        #
        # This section Installs the product itself
        #************************************************************ 
        SPInstall InstallSharePoint 
        {
            PsDscRunAsCredential = $SPSetupAccount
            BinaryDir            = "$binaryPath\SharePoint"
            ProductKey           = $DscStudio.ProductKey
            DataPath             = $DscStudio.InstallDataPath
            InstallPath          = $DscStudio.InstallPath
            Ensure               = "Present"
            DependsOn            = "[SPInstallPrereqs]InstallPreReqs"
        }

        #*************************************************************
        # Install app fabric CU
        #
        # For SP2013 install App Fabric CU7, which should be included
        # in the same directory as the offline prereq installer files
        # Download from https://support.microsoft.com/en-us/kb/3092423
        #*************************************************************
        if ($DscStudio.ProductVersion -eq "2013") 
        {
            Script InstallAppFabricCU7 
            {
                GetScript  = { return @{} }
                TestScript = {
                    $registryKey = Get-Item -Path HKLM:\SOFTWARE\Classes\Installer\Patches\014C4FD0FAEDDE54794B4999D7605596
                    if ($null -eq $registryKey) 
                    {
                        return $false
                    } 
                    else 
                    {
                        return $true
                    }
                }
                SetScript = "Start-Process -FilePath (Join-Path '$($DscStudio.LocalBinaries)' 'SharePoint\PrerequisiteInstallerFiles\AppFabric-KB3092423-x64-ENU.exe') -ArgumentList '/w /quiet' -Wait -PassThru"
                DependsOn = "[SPInstallPrereqs]InstallPrereqs"
            }
        }

        #**********************************************************
        # Server configuration
        #
        # This section of the configuration includes details of the
        # server level configuration, such as disks, registry
        # settings etc.
        #********************************************************** 

        xCredSSP CredSSPServer { Ensure = "Present"; Role = "Server"; } 
        xCredSSP CredSSPClient { Ensure = "Present"; Role = "Client"; DelegateComputers = $AllNodes.NodeName; }

        #**********************************************************
        # IIS clean up
        #
        # This section removes all default sites and application
        # pools from IIS as they are not required
        #**********************************************************

        xWebAppPool RemoveDotNet2Pool         { Name = ".NET v2.0";            Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebAppPool RemoveDotNet2ClassicPool  { Name = ".NET v2.0 Classic";    Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebAppPool RemoveDotNet45Pool        { Name = ".NET v4.5";            Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebAppPool RemoveDotNet45ClassicPool { Name = ".NET v4.5 Classic";    Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebAppPool RemoveClassicDotNetPool   { Name = "Classic .NET AppPool"; Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebAppPool RemoveDefaultAppPool      { Name = "DefaultAppPool";       Ensure = "Absent"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        xWebSite    RemoveDefaultWebSite      { Name = "Default Web Site";     Ensure = "Absent"; PhysicalPath = "C:\inetpub\wwwroot"; DependsOn = "[SPInstallPrereqs]InstallPreReqs" }
        

        #**********************************************************
        # Basic farm configuration
        #
        # This section creates the new SharePoint farm object, and
        # provisions generic services and components used by the
        # whole farm
        #**********************************************************
        $runCentralAdmin = $false
        if ($node.ServerRole -eq "Single Server Farm" `
            -or $node.ServerRole -eq "Application Server" `
            -or $node.ServerRole -eq "Application Server with Search")
        {
            $runCentralAdmin = $true
        }

        switch ($DscStudio.ProductVersion) 
        {
            "2013" {
                SPFarm SharePointFarm
                {
                    Ensure                    = "Present"
                    DatabaseServer            = $DscStudio.SqlServerFarm
                    FarmConfigDatabaseName    = $DscStudio.DatabasePrefix + $DscStudio.FarmConfigDb
                    Passphrase                = $FarmPassPhrase
                    FarmAccount               = $FarmAccount
                    PsDscRunAsCredential      = $SPSetupAccount
                    AdminContentDatabaseName  = $DscStudio.DatabasePrefix + $DscStudio.AdminContentDb
                    CentralAdministrationPort = $DscStudio.CentralAdminPort
                    RunCentralAdmin           = $runCentralAdmin
                    DependsOn                 = "[SPInstall]InstallSharePoint"
                }
            }
            "2016" {
                SPFarm SharePointFarm
                {
                    Ensure                    = "Present"
                    DatabaseServer            = $DscStudio.SqlServerFarm
                    FarmConfigDatabaseName    = $DscStudio.DatabasePrefix + $DscStudio.FarmConfigDb
                    Passphrase                = $FarmPassPhrase
                    FarmAccount               = $FarmAccount
                    PsDscRunAsCredential      = $SPSetupAccount
                    AdminContentDatabaseName  = $DscStudio.DatabasePrefix + $DscStudio.AdminContentDb
                    CentralAdministrationPort = $DscStudio.CentralAdminPort
                    RunCentralAdmin           = $runCentralAdmin
                    ServerRole                = $MinRole
                    DependsOn                 = "[SPInstall]InstallSharePoint"
                }
            }
        }

        File UlsLogPath 
        {
            Ensure          = 'Present'
            DestinationPath = $DscStudio.UlsLogPath
            Type            = 'Directory'
            DependsOn       = "[SPFarm]SharePointFarm"
        }

        if ($DscStudio.UlsLogPath -ne $DscStudio.UsageLogPath)
        {
            File UsageLogPath 
            {
                Ensure          = 'Present'
                DestinationPath = $DscStudio.UsageLogPath
                Type            = 'Directory'
                DependsOn       = "[SPFarm]SharePointFarm"
            }
        }

        if ($node.NodeName -eq $FarmServer) 
        {    
            if ($DscStudio.AlwaysOnEnabled) 
            {
                SPDatabaseAAG FarmDBAAG 
                {
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.FarmConfigDb
                    AGName               = $DscStudio.ConfigDBGroupName
                    FileShare            = $DscStudio.AGFileShare
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPFarm]SharePointFarm"
                }
                
                SPDatabaseAAG AdminContentDBAAG 
                {
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.AdminContentDb
                    AGName               = $DscStudio.ConfigDBGroupName
                    FileShare            = $DscStudio.AGFileShare
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPFarm]SharePointFarm"
                }
            }
        } 


        # Apply farm wide configuration and logical components only on the first server
        if ($node.NodeName -eq $FarmServer) 
        {
            SPManagedAccount ServicePoolManagedAccount
            {
                AccountName          = $ServicePoolManagedAccount.UserName
                Account              = $ServicePoolManagedAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]SharePointFarm"
            }
            SPManagedAccount WebPoolManagedAccount
            {
                AccountName          = $WebPoolManagedAccount.UserName
                Account              = $WebPoolManagedAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]SharePointFarm"
            }
            SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
            {
                PsDscRunAsCredential        = $SPSetupAccount
                LogPath                     = $DscStudio.UlsLogPath
                LogSpaceInGB                = $DscStudio.UlsLogSize
                DaysToKeepLogs              = $DscStudio.UlsDaysToKeep
                LogMaxDiskSpaceUsageEnabled = $true
                DependsOn                   = "[SPFarm]SharePointFarm"
            }
            
            SPUsageApplication UsageApplication 
            {
                Name                  = "Usage Service Application"
                DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.UsageDb
                DatabaseServer        = $DscStudio.SqlServerFarm
                UsageLogLocation      = $DscStudio.UsageLogPath
                PsDscRunAsCredential  = $SPSetupAccount
                DependsOn             = "[SPFarm]SharePointFarm"
            }
            if ($DscStudio.AlwaysOnEnabled) 
            {
                SPDatabaseAAG UsageDBAAG 
                {
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.UsageDb
                    AGName               = $DscStudio.ConfigDBGroupName
                    FileShare            = $DscStudio.AGFileShare
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPUsageApplication]UsageApplication"
                }
            }
            
            SPStateServiceApp StateServiceApp
            {
                Name                 = "State Service Application"
                DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.StateServiceDb
                DatabaseServer       = $DscStudio.SqlServerFarm
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]SharePointFarm"
            }
            if ($DscStudio.AlwaysOnEnabled) 
            {
                SPDatabaseAAG StateServiceDBAAG 
                {
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.StateServiceDb
                    AGName               = $DscStudio.ConfigDBGroupName
                    FileShare            = $DscStudio.AGFileShare
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPStateServiceApp]StateServiceApp"
                }
            }
            
            SPSessionStateService StateServiceApp
            {
                DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SessionStateServiceDb
                DatabaseServer       = $DscStudio.SqlServerFarm
                Ensure               = "Present"
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]SharePointFarm"
            }

            if ($DscStudio.AlwaysOnEnabled) 
            {
                SPDatabaseAAG SessionStateServiceDBAAG 
                {
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SessionStateServiceDb
                    AGName               = $DscStudio.ConfigDBGroupName
                    FileShare            = $DscStudio.AGFileShare
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPSessionStateService]StateServiceApp"
                }
            }
        
            SPFarmAdministrators FarmAdmins
            {
                Name                  = "Farm Administrators"
                MembersToInclude      = $DscStudio.FarmAdmins
                PsDscRunAsCredential  = $SPSetupAccount
                DependsOn             = "[SPFarm]SharePointFarm"
            }

            if ($DscStudio.OutgoingMailEnabled -eq $true) 
            {
                SPOutgoingEmailSettings OutgoingEmail
                {
                    WebAppUrl            = "http://$($FarmServer.Substring(0, $FarmServer.IndexOf("."))):$($DscStudio.CentralAdminPort)"
                    SMTPServer           = $DscStudio.SMTPServer
                    FromAddress          = $DscStudio.FromMailAddress
                    ReplyToAddress       = $DscStudio.ReplyToAddress
                    CharacterSet         = 65001
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPFarm]SharePointFarm"
                }
            }
            
            if ($DscStudio.AntiVirusEnabled -eq $true) 
            {
                SPAntivirusSettings AntivirusSettings 
                {
                    ScanOnDownload        = $DscStudio.AVScanOnDownload
                    ScanOnUpload          = $DscStudio.AVScanOnUpload
                    AllowDownloadInfected = $DscStudio.AVAllowDownloadInfected
                    AttemptToClean        = $DscStudio.AVAttemptToClean
                    TimeoutDuration       = $DscStudio.AVTimeoutDuration
                    NumberOfThreads       = $DscStudio.AVNumberOfThreads
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPFarm]SharePointFarm"
                }
            }

            if ($DscStudio.EnableOfficeOnlineServer) 
            {
                SPOfficeOnlineServerBinding OfficeWebAppsBinding
                {
                    DnsName               = $DscStudio.OosDnsName
                    Zone                  = $DscStudio.OosZone
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPFarm]SharePointFarm"
                }
            }

            # Deploy WSP packages to the local farm
            foreach ($solution in $DscStudio.FarmSolutions) 
            {
                SPFarmSolution "FarmSolution-$($solution.Name)"
                {
                    Name                 = $solution.Name
                    LiteralPath          = $solution.LiteralPath
                    Deployed             = $solution.Deployed
                    Ensure               = "Present"
                    WebApplications      = $solution.WebApplications.Split(',')
                    SolutionLevel        = $solution.CompatLevel 
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPFarm]SharePointFarm"
                }
            }
        }
        

        #**********************************************************
        # Web applications
        #
        # This section creates the web applications in the 
        # SharePoint farm, as well as managed paths and other web
        # application settings
        #**********************************************************

        if ($node.NodeName -eq $FarmServer)
        {
            foreach($webApp in $DscStudio.WebApplications)
            {
                $webAppInternalName = $webApp.Name.Replace(" ", "")
                $webAppUri = [Uri]::new($webApp.Url)

                $contentDBsForThisWebApp = $DscStudio.ContentDatabases | Where-Object -FilterScript {
                    $_.WebAppUrl -eq $webApp.Url
                }

                if ($null -eq $contentDBsForThisWebApp)
                {
                    throw ("No content databases were added for web app '$($webApp.Name)'. " + `
                           "Please add at least one content database for each web application")
                }

                $sitesForThisWebApp = $DscStudio.SiteCollections | Where-Object -FilterScript {
                    $_.WebAppUrl -eq $webApp.Url
                }

                $managedPathsForThisWebApp = $DscStudio.ManagedPaths | Where-Object -FilterScript {
                    $_.WebAppUrl -eq $webApp.Url
                }

                SPWebApplication $webAppInternalName
                {
                    Name                   = $webApp.Name
                    ApplicationPool        = $webApp.AppPool
                    ApplicationPoolAccount = $webApp.AppPoolAccount
                    AllowAnonymous         = $webApp.Anonymous
                    DatabaseName           = $DscStudio.DatabasePrefix + (($contentDBsForThisWebApp | Select-Object -First 1).Name)
                    DatabaseServer         = $DscStudio.SqlServerContent
                    Url                    = $webApp.Url
                    Port                   = $webAppUri.Port
                    HostHeader             = $webApp.IISHostHeader
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn              = "[SPManagedAccount]WebPoolManagedAccount"
                }

                $fileHandling = "Strict"
                if ($webApp.AllowPermissive -eq $true)
                {
                    $fileHandling = "Permissive"
                }

                SPWebAppAuthentication "$($webAppInternalName)Authentication"
                {
                    WebAppUrl            = $webApp.Url
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPWebApplication]$webAppInternalName"
                    Default              = @(
                        MSFT_SPWebAppAuthenticationMode {
                            AuthenticationMethod = $webApp.Authentication
                        }
                    )
                }

                SPWebAppGeneralSettings "$($webAppInternalName)GeneralSettings"
                {
                    Url                        = $webApp.Url
                    TimeZone                   = $webApp.TimeZone
                    BrowserFileHandling        = $fileHandling
                    MaximumUploadSize          = $webApp.MaximumUploadSize
                    RecycleBinCleanupEnabled   = $webApp.RecycleBinCleanupEnabled
                    RecycleBinEnabled          = $webApp.RecycleBinEnabled
                    RecycleBinRetentionPeriod  = $webApp.RecycleBinRetentionPeriod
                    SecondStageRecycleBinQuota = $webApp.SecondStageRecycleBinQuota
                    PsDscRunAsCredential       = $SPSetupAccount
                    DependsOn                  = "[SPWebApplication]$webAppInternalName"
                }
                
                $contentDBsForThisWebApp | ForEach-Object -Process {
                    $dbResourceName = "$($webAppInternalName)ContentDB$($_.Name)"
                    SPContentDatabase $dbResourceName 
                    {
                        Name                 = $DscStudio.DatabasePrefix + $_.Name
                        DatabaseServer       = $DscStudio.SqlServerContent
                        WebAppUrl            = $webApp.Url
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPWebApplication]$webAppInternalName"
                    } 
                    
                    if ($DscStudio.AlwaysOnEnabled) 
                    {
                        SPDatabaseAAG "$($dbResourceName)AAG"
                        {
                            DatabaseName         = $DscStudio.DatabasePrefix + $_.Name
                            AGName               = $DscStudio.ContentDBGroupName
                            FileShare            = $DscStudio.AGFileShare
                            PsDscRunAsCredential = $SPSetupAccount
                            DependsOn            = "[SPContentDatabase]$dbResourceName"
                        }
                    }
                }

                # If using host named site collections, create the empty path based site here
                if ($webApp.UseHostNamedSiteCollections -eq $true)
                {
                    SPSite HNSCRootSite
                    {
                        Url                      = $webApp.Url
                        OwnerAlias               = $SPSetupAccount.Username
                        Name                     = "Host name site collections root site"
                        Template                 = "STS#0"
                        PsDscRunAsCredential     = $SPSetupAccount
                        DependsOn                = "[SPWebApplication]$webAppInternalName"
                    }
                }

                foreach($managedPath in $managedPathsForThisWebApp)
                {
                    SPManagedPath "$($webAppInternalName)Path$($managedPath.Path)"
                    {
                        WebAppUrl            = $webApp.Url
                        PsDscRunAsCredential = $SPSetupAccount
                        RelativeUrl          = $managedPath.Path
                        Explicit             = $managedPath.Explicit
                        HostHeader           = $webApp.UseHostNamedSiteCollections
                        DependsOn            = "[SPWebApplication]$webAppInternalName"
                    }
                }
                
                SPCacheAccounts "$($webAppInternalName)CacheAccounts"
                {
                    WebAppUrl              = $webApp.Url
                    SuperUserAlias         = $webApp.SuperUser
                    SuperReaderAlias       = $webApp.SuperReader
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn              = "[SPWebApplication]$webAppInternalName"
                }

                foreach($siteCollection in $sitesForThisWebApp)
                {
                    $uniqueId = New-Guid
                    $internalSiteName = "$($webAppInternalName)Site$($siteCollection.Name.Replace(' ', ''))-$uniqueId"
                    if ($webApp.UseHostNamedSiteCollections -eq $true)
                    {
                        SPSite $internalSiteName
                        {
                            Url                      = $siteCollection.Url
                            OwnerAlias               = $siteCollection.Owner
                            HostHeaderWebApplication = $webApp.Url
                            Name                     = $siteCollection.Name
                            Template                 = $siteCollection.Template
                            PsDscRunAsCredential     = $SPSetupAccount
                            DependsOn                = "[SPWebApplication]$webAppInternalName"
                        }
                    } 
                    else
                    {
                        SPSite $internalSiteName
                        {
                            Url                      = $siteCollection.Url
                            OwnerAlias               = $siteCollection.Owner
                            Name                     = $siteCollection.Name
                            Template                 = $siteCollection.Template
                            PsDscRunAsCredential     = $SPSetupAccount
                            DependsOn                = "[SPWebApplication]$webAppInternalName"
                        }
                    }
                }
            }
        }
        
        #**********************************************************
        # Service instances
        #
        # This section describes which services should be running
        # and not running on the server
        #**********************************************************
        
        $serviceMatrix = @(
            @{
                Name = "Access Services"
                ServerRoles = @("SingleServerFarm", "WebFrontEnd", "WebFrontEndWithDistributedCache")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionAccessServices -eq $true }
                )
            }
            @{
                Name = "Access Services 2010"
                ServerRoles = @("SingleServerFarm", "WebFrontEnd", "WebFrontEndWithDistributedCache")
                Versions = @("2013", "2016")
                Tests = @(
                    # Reserving for future use to add support for Access services 2010
                    { $false }
                )
            }
            @{
                Name = "App Management Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionAppManagement -eq $true }
                )
            }
            @{
                Name = "Application Discovery and Load Balancer Service"
                ServerRoles = @("SingleServerFarm", "Application", "Search", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "Business Data Connectivity Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionBCS -eq $true }
                )
            }
            @{
                Name = "Claims to Windows Token Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    # Forcing a false here as I can't seem to figure out what scenarios MinRole needs it
                    # We can manually start it for 2013 deployments that actually need it
                    { $false }
                )
            }
            @{
                Name = "Excel Calculation Services"
                ServerRoles = @("SingleServerFarm", "Application", "ApplicationWithSearch")
                Versions = @("2013")
                Tests = @(
                    { $DscStudio.ProvisionExcel -eq $true }
                )
            }
            #TODO: Dist cache was removed from here, need to handle with its resource
            @{
                Name = "Machine Translation Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    # force a false return, reserving this for future addition of support for this 
                    { $false }
                )
            }
            @{
                Name = "Managed Metadata Web Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionMMS -eq $true }
                )
            }
            @{
                Name = "Microsoft SharePoint Foundation Administration"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "DistributedCache", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "Microsoft SharePoint Foundation Incoming E-Mail"
                ServerRoles = @("SingleServerFarm", "Application", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "Microsoft SharePoint Foundation Subscription Settings Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSubscriptionSettings -eq $true }
                )
            }
            @{
                Name = "Microsoft SharePoint Foundation Timer"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "DistributedCache", "Search", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "Microsoft SharePoint Foundation Web Application"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "Microsoft SharePoint Foundation Workflow Timer Service"
                ServerRoles = @("SingleServerFarm", "Application", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @()
            }
            @{
                Name = "PerformancePoint Service"
                ServerRoles = @("SingleServerFarm", "WebFrontEnd", "WebFrontEndWithDistributedCache")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionPerfPoint -eq $true }
                )
            }
            @{
                Name = "PowerPoint Conversion Service"
                ServerRoles = @("SingleServerFarm", "Application", "ApplicationWithSearch")
                Versions = @("2016")
                Tests = @(
                    # force a false return, reserving this for future addition of support for this 
                    { $false }
                )
            }
            @{
                Name = "Project Server Application Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2016")
                Tests = @(
                    # force a false return, reserving this for future addition of project server support
                    { $false }
                )
            }
            @{
                Name = "Search Administration Web Service"
                ServerRoles = @("SingleServerFarm", "Search", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSearch -eq $true }
                )
            }
            @{
                Name = "Search Host Controller Service"
                ServerRoles = @("SingleServerFarm", "Search", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSearch -eq $true }
                )
            }
            @{
                Name = "Search Query and Site Settings Service"
                ServerRoles = @("SingleServerFarm", "Search", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSearch -eq $true }
                )
            }
            @{
                Name = "Secure Store Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSecureStore -eq $true }
                )
            }
            @{
                Name = "SharePoint Server Search"
                ServerRoles = @("SingleServerFarm", "Search", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionSearch -eq $true }
                )
            }
            @{
                Name = "User Profile Service"
                ServerRoles = @("SingleServerFarm", "Application", "WebFrontEnd", "WebFrontEndWithDistributedCache", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionUserProfiles -eq $true }
                )
            }
            @{
                Name = "Visio Graphics Service"
                ServerRoles = @("SingleServerFarm", "WebFrontEnd", "WebFrontEndWithDistributedCache")
                Versions = @("2013", "2016")
                Tests = @(
                    { $DscStudio.ProvisionVisio -eq $true }
                )
            }
            @{
                Name = "Word Automation Services"
                ServerRoles = @("SingleServerFarm", "Application", "ApplicationWithSearch")
                Versions = @("2013", "2016")
                Tests = @(
                    # force a false return, reserving this for future addition of support for this 
                    { $false }
                )
            }
        )

        switch ($DscStudio.ProductVersion)
        {
            "2013" {
                # Do service instances manually for 2013

                $serviceInstances = @()
                
                $serviceMatrix | ForEach-Object -Process {

                    $addThisService = $true
                    $localService = $_

                    # Test server role
                    if ($localService.ServerRoles -notcontains $OAServerRole) 
                    {
                        $addThisService = $false
                    }

                    # Test product version
                    if ($localService.Versions -notcontains $DscStudio.ProductVersion) 
                    {
                        $addThisService = $false
                    }

                    # Test additional tests
                    if ($null -ne $localService.Tests -and $localService.Tests.Count -gt 0)
                    {
                        $localService.Tests | ForEach-Object -Process {
                            Invoke-Command -ScriptBlock $_ -NoNewScope
                        } | ForEach-Object -Process {
                            if ($_ -eq $false)
                            {
                                $addThisService = $false
                            }
                        }
                    }

                    if ($addThisService -eq $true)
                    {
                        $serviceInstances += $localService.Name
                    }
                }

                $serviceInstances | ForEach-Object -Process {

                    $internalServiceName = $_.Replace(" ", "")

                    SPServiceInstance "SPService-$internalServiceName"
                    {  
                        Name                 = $_
                        Ensure               = "Present"
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPFarm]SharePointFarm"
                    }
                }
            }
            "2016" {
                # Let service instances be started by MinRole

                SPMinRoleCompliance SPMinRoleCompliance
                {
                    State                = 'Compliant'
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPFarm]SharePointFarm"
                }
            }
        }
        
        # Front end service instances
        if ($OAServerRole -eq "WebFrontEnd" `
            -or $OAServerRole -eq "WebFrontEnd" `
            -or $OAServerRole -eq "SingleServer") 
        {
            # Perform IIS bindings with SSL on each web app for the front ends
            foreach($webApp in $DscStudio.WebApplications)
            {
                $webAppInternalName = $webApp.Name.Replace(" ", "")

                if ($webApp.ConfigureSSLBindings) 
                {
                    xWebSite "$($webAppInternalName)SSLBinding"
                    {
                        Name = $webApp.Name
                        Ensure = "Present"
                        State = "Started"
                        BindingInfo = @(MSFT_xWebBindingInformation {
                            Protocol              = [Uri]::new($webApp.Url).Scheme
                            Port                  = [Uri]::new($webApp.Url).Port
                            CertificateStoreName  = "MY"
                            CertificateThumbprint = $webApp.CertificateThumbprint
                            HostName              = $webApp.IisHostHeader
                            IPAddress             = '*'
                        })
                    }
                }
            }         
        }
        
        if ($OAServerRole -eq "DistributedCache" `
            -or $OAServerRole -eq "WebFrontEndWithDistributedCache" `
            -or $OAServerRole -eq "SingleServer") 
        {
            WaitForAll WaitForServiceAppAccount 
            {
                ResourceName = "[SPManagedAccount]ServicePoolManagedAccount"
                NodeName = $FarmServer
                RetryIntervalSec = 60
                RetryCount = 60
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPFarm]SharePointFarm"
            }

            $cacheServers = ($AllNodes | Where-Object -FilterScript {
                $_.ServerRole -eq "Web Front End with Distributed Cache" `
                -or $_.ServerRole -eq "Distributed Cache" `
                -or $_.ServerRole -eq "Single Server Farm"
            }).NodeName | ForEach-Object -Process {
                return $_.Substring(0, $_.IndexOf(".")) 
            }

            SPDistributedCacheService EnableDistributedCache
            {
                Name                 = "AppFabricCachingService"
                Ensure               = "Present"
                CacheSizeInMB        = $DscStudio.DistributedCacheSize
                ServiceAccount       = $ServicePoolManagedAccount.UserName
                PsDscRunAsCredential = $SPSetupAccount
                CreateFirewallRules  = $true
                ServerProvisionOrder = $cacheServers
                DependsOn            = "[WaitForAll]WaitForServiceAppAccount"
            }
        }

        
        #**********************************************************
        # Service applications
        #
        # This section creates service applications and required
        # dependencies
        #**********************************************************

        if ($node.NodeName -eq $FarmServer) 
        {
            $serviceAppPoolName = "SharePoint Service Applications"
            SPServiceAppPool MainServiceAppPool
            {
                Name                 = $serviceAppPoolName
                ServiceAccount       = $ServicePoolManagedAccount.UserName
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]SharePointFarm"
            }

            if ($DscStudio.ProvisionUserProfiles -eq $true) 
            {
                # Runs as farm account by design to ensure correct DB schema owner
                SPUserProfileServiceApp UserProfileServiceApp
                {
                    Name                 = "User Profile Service Application"
                    ApplicationPool      = $serviceAppPoolName
                    MySiteHostLocation   = $DscStudio.MySiteHostUrl
                    ProfileDBName        = $DscStudio.DatabasePrefix + $DscStudio.ProfileDBName
                    ProfileDBServer      = $DscStudio.SqlServerFarm
                    SocialDBName         = $DscStudio.DatabasePrefix + $DscStudio.SocialDBName
                    SocialDBServer       = $DscStudio.SqlServerFarm
                    SyncDBName           = $DscStudio.DatabasePrefix + $DscStudio.SyncDBName
                    SyncDBServer         = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPServiceAppPool]MainServiceAppPool"
                }

                if ($DscStudio.ProvisionUserProfileSync -eq $true -and $DscStudio.ProductVersion -eq "2013") 
                {
                    SPUserProfileSyncService UserProfileSyncService
                    {
                        UserProfileServiceAppName = "User Profile Service Application" 
                        FarmAccount               = $FarmAccount
                        PsDscRunAsCredential      = $SPSetupAccount
                        DependsOn                 = "[SPUserProfileServiceApp]UserProfileServiceApp"
                    }
                } 
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "ProfileDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.ProfileDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPUserProfileServiceApp]UserProfileServiceApp"
                    }
                    
                    SPDatabaseAAG "SocialDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SocialDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPUserProfileServiceApp]UserProfileServiceApp"
                    }
                    
                    SPDatabaseAAG "SyncDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SyncDBName
                        AGName               = $DscStudio.ConfigDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPUserProfileServiceApp]UserProfileServiceApp"
                    }
                }
            }
        
            if ($DscStudio.ProvisionSecureStore -eq $true) 
            {
                SPSecureStoreServiceApp SecureStoreServiceApp
                {
                    Name                  = "Secure Store Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    AuditingEnabled       = $true
                    AuditlogMaxSize       = 30
                    DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.SecureStoreDBName
                    DatabaseServer        = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "SecureStoreDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SecureStoreDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSecureStoreServiceApp]SecureStoreServiceApp"
                    }
                } 
            }
            
            if ($DscStudio.ProvisionMMS -eq $true) 
            {
                SPManagedMetaDataServiceApp ManagedMetadataServiceApp
                {  
                    Name                 = "Managed Metadata Service Application"
                    PsDscRunAsCredential = $SPSetupAccount
                    ApplicationPool      = $serviceAppPoolName
                    DatabaseServer       = $DscStudio.SqlServerFarm
                    DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.MMSDBName
                    DependsOn            = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "ManagedMetadataDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.MMSDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPManagedMetaDataServiceApp]ManagedMetadataServiceApp"
                    }
                }
            }
            
            if ($DscStudio.ProvisionBCS -eq $true) 
            {
                SPBCSServiceApp BCSServiceApp
                {
                    Name                  = "BCS Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.BCSDBName
                    DatabaseServer        = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "BCSDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.BCSDBName
                        AGName               = $DscStudio.ConfigDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPBCSServiceApp]BCSServiceApp"
                    }
                }
            }
        
            if ($DscStudio.ProvisionAppManagement -eq $true)
            {
                
                $appCatalogSiteName = ""
                if ($DscStudio.SiteCollections.Template -notcontains "APPCATALOG#0") 
                {
                    throw ("The config data is set to provision app infrastructure, however " + `
                           "there is no site collection to host the app catalog. Add a site " + `
                           "collection to the config data that uses the site template " + `
                           "'APPCATALOG#0' and it will be set as the app catalog site.")
                } 
                else 
                {
                    $siteCollection = $DscStudio.SiteCollections  | Where-Object -FilterScript {
                        $_.Template -eq "APPCATALOG#0"
                    } 
                    $webApp = $DscStudio.WebApplications | Where-Object -FilterScript {
                        $_.url -eq $siteCollection.WebAppUrl
                    }
                    $appCatalogSiteName = "[SPSite]$($webApp.Name.Replace(' ', ''))Site$($siteCollection.Name.Replace(' ', ''))"
                }
                
                SPAppManagementServiceApp AppManagementServiceApp
                {
                    Name                  = "App Management Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.AppManagementDBName
                    DatabaseServer        = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "AppManagementDBAAG" 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.AppManagementDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPAppManagementServiceApp]AppManagementServiceApp"
                    }
                }
                
                SPAppCatalog AppCatalog 
                {
                    SiteUrl              = $siteCollection.Url
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPSite]$InternalSiteName"
                }
                
                SPAppDomain AppDomains 
                {
                    AppDomain            = $DscStudio.AppManagementDomain
                    Prefix               = $DscStudio.AppManagementPrefix
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPAppManagementServiceApp]AppManagementServiceApp"
                }
            }

            if ($DscStudio.ProvisionSubscriptionSettings -eq $true)
            {
                SPSubscriptionSettingsServiceApp SubscriptionSettingsServiceApp
                {
                    Name                  = "Subscription Settings Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.SubscriptionSettingsDBName
                    DatabaseServer        = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG "SubscriptionSettingsDBAAG"
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SubscriptionSettingsDBName
                        AGName               = $DscStudio.ContentDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSubscriptionSettingsServiceApp]SubscriptionSettingsServiceApp"
                    }
                }
            }
            
            if ($DscStudio.ProvisionAccessServices -eq $true)
            {
                SPAccessServiceApp AccessServicesServiceApp
                {
                    Name                  = "Access Services 2013 Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    DatabaseServer        = $DscStudio.AccessServicesDBHost
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }        
            }
            
            if ($DscStudio.ProvisionExcel -eq $true -and $DSCStudio.ProductVersion -eq "2013")
            {
                SPExcelServiceApp ExcelServices
                {
                    Name                  = "Excel Services Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
            }
            
            if ($DscStudio.ProvisionVisio -eq $true)
            {
                SPVisioServiceApp VisioServices
                {
                    Name                  = "Visio Services Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
            }
            
            if ($DscStudio.ProvisionPerfPoint -eq $true)
            {
                SPPerformancePointServiceApp PerformancePoint
                {
                    Name                  = "PerformancePoint Service Application"
                    ApplicationPool       = $serviceAppPoolName
                    DatabaseName          = $DscStudio.DatabasePrefix + $DscStudio.PerfPointDBName
                    DatabaseServer        = $DscStudio.SqlServerFarm
                    PsDscRunAsCredential  = $SPSetupAccount
                    DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
                }
            }

            if ($DscStudio.ProvisionSearch -eq $true) 
            {
                SPSearchServiceApp SearchServiceApp
                {  
                    Name                        = "Search Service Application"
                    DatabaseName                = $DscStudio.DatabasePrefix + $DscStudio.SearchDBName
                    DatabaseServer              = $DscStudio.SqlServerSearch
                    ApplicationPool             = $serviceAppPoolName
                    DefaultContentAccessAccount = $DefaultContentAccessAccount
                    PsDscRunAsCredential        = $SPSetupAccount
                    WindowsServiceAccount       = $ServicePoolManagedAccount
                    DependsOn                   = "[SPServiceAppPool]MainServiceAppPool"
                }
                
                if ($DscStudio.AlwaysOnEnabled) 
                {
                    SPDatabaseAAG SearchServieAppDBAAG 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SearchDBName
                        AGName               = $DscStudio.SearchDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSearchServiceApp]SearchServiceApp"
                    }                

                    SPDatabaseAAG SearchCrawlStoreDBAAG 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SearchDBName + "_CrawlStore"
                        AGName               = $DscStudio.SearchDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        Ensure               = "Present"
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSearchServiceApp]SearchServiceApp"
                    }

                    SPDatabaseAAG SearchAnalyticsReportingStoreDBAAG 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SearchDBName + "_AnalyticsReportingStore"
                        AGName               = $DscStudio.SearchDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        Ensure               = "Present"
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSearchServiceApp]SearchServiceApp"
                    }

                    SPDatabaseAAG SearchLinksStoreDBAAG 
                    {
                        DatabaseName         = $DscStudio.DatabasePrefix + $DscStudio.SearchDBName + "_LinksStore"
                        AGName               = $DscStudio.SearchDBGroupName
                        FileShare            = $DscStudio.AGFileShare
                        Ensure               = "Present"
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[SPSearchServiceApp]SearchServiceApp"
                    }
                }
                
                $searchFrontEnds = ($AllNodes | Where-Object -FilterScript {
                    $_.ServerRole -eq "Search" `
                    -or $_.ServerRole -eq "Application Server with Search" `
                    -or $_.ServerRole -eq "Single Server Farm"
                }).NodeName | ForEach-Object -Process {
                    return $_.Substring(0, $_.IndexOf("."))
                }
                
                $searchBackEnds = ($AllNodes | Where-Object -FilterScript {
                    $_.ServerRole -eq "Search" `
                    -or $_.ServerRole -eq "Application Server with Search" `
                    -or $_.ServerRole -eq "Single Server Farm"
                }).NodeName | ForEach-Object -Process {
                    return $_.Substring(0, $_.IndexOf("."))
                }

                SPSearchTopology SearchTopology
                {
                    ServiceAppName          = "Search Service Application"
                    Admin                   = $searchBackEnds
                    Crawler                 = $searchBackEnds
                    QueryProcessing         = $searchFrontEnds
                    ContentProcessing       = $searchBackEnds
                    AnalyticsProcessing     = $searchBackEnds
                    IndexPartition          = $searchFrontEnds
                    FirstPartitionDirectory = "$($DscStudio.SearchIndexPath.TrimEnd("\"))\0"
                    PsDscRunAsCredential    = $SPSetupAccount
                    DependsOn               = "[SPSearchServiceApp]SearchServiceApp"
                }
            }
        }
    }
}
