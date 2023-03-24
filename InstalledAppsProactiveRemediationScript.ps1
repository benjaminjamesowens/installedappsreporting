#**************************** Part to fill ************************************
# Log analytics part
$CustomerId = "faf81dd7-d096-4918-a832-6e0642378e81" # Log Analytics Workspace ID
$SharedKey = 'MqYanoB9wPrPvQRTVLgv6K2KKKsQLEyd2WH2uXxAhhs3uxGHH8M+dFCASRXDV6il2F1F/mkq32jx8hqwvNIrPQ==' # Log Analytics Workspace Primary Key
$LogType = "InstalledApps_EMGTest" # Custom log to create in Log Analytics
$TimeStampField = "" # let to blank
#*******************************************************************************

# Log analytics functions
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# Collecting information from device
$ComputerSerialNumber = Get-WmiObject win32_bios | select -ExpandProperty Serialnumber
$ComputerName = $env:computername
$DateCollected = Get-Date -Format "MM/dd/yyyy HH:mm"

Function Convert-AzureAdSidToObjectId {
<#
.SYNOPSIS
Convert a Azure AD SID to Object ID
 
.DESCRIPTION
Converts an Azure AD SID to Object ID.
Author: Oliver Kieselbach (oliverkieselbach.com)
The script is provided "AS IS" with no warranties.
 
.PARAMETER ObjectID
The SID to convert
#>

    param([String] $Sid)

    $text = $sid.Replace('S-1-12-1-', '')
    $array = [UInt32[]]$text.Split('-')

    $bytes = New-Object 'Byte[]' 16
    [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
    [Guid]$guid = $bytes

    return $guid
}

<#
.SYNOPSIS
    Adds note properties containing the last modified time and class name of a 
    registry key.
.DESCRIPTION
    Add-RegKeyMember function uses the unmanged RegQueryInfoKey Win32 function
    to get a key's last modified time and class name. It can take a RegistryKey 
    object (which Get-Item and Get-ChildItem output) or a path to a registry key.
.EXAMPLE
    PS c:\> Get-Item HKLM:\SOFTWARE | Get-RegWritetime | Select Name, LastWriteTime
    Show the name and last write time of HKLM:\SOFTWARE
.EXAMPLE
    PS C:\> Get-RegWritetime HKLM:\SOFTWARE | Select Name, LastWriteTime
    Show the name and last write time of HKLM:\SOFTWARE
.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SOFTWARE | Get-RegWritetime | Select Name, LastWriteTime
    Show the name and last write time of HKLM:\SOFTWARE's child keys
.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Get-RegWritetime | where classname | select name, classname
    Show the name and class name of child keys under Lsa that have a class name defined.
.EXAMPLE
    PS C:\> Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-Regtime HKLM:\SOFTWARE | Select Name, LastWriteTime | where lastwritetime -gt (Get-Date).AddDays(-30) | 
    >> select PSChildName, @{ N="DisplayName"; E={gp $_.PSPath | select -exp DisplayName }}, @{ N="Version"; E={gp $_.PSPath | select -exp DisplayVersion }}, lastwritetime |
    >> sort lastwritetime
    Show applications that have had their registry key updated in the last 30 days (sorted by the last time the key was updated).
    NOTE: On a 64-bit machine, you will get different results depending on whether or not the command was executed from a 32-bit
    or 64-bit PowerShell prompt.
#>
Function Get-RegWriteTime {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="ByKey", Position=0, ValueFromPipeline=$true)]
        [ValidateScript({ $_ -is [Microsoft.Win32.RegistryKey] })]
        # Registry key object returned from Get-ChildItem or Get-Item. Instead of requiring the type to
        # be [Microsoft.Win32.RegistryKey], validation has been moved into a [ValidateScript] parameter
        # attribute. In PSv2, PS type data seems to get stripped from the object if the [RegistryKey]
        # type is an attribute of the parameter.
        $RegistryKey,
        [Parameter(Mandatory=$true, ParameterSetName="ByPath", Position=0)]
        # Path to a registry key
        [string] $Path
    )

    begin {
        # Define the namespace (string array creates nested namespace):
        $Namespace = "CustomNamespace", "SubNamespace"

        # Make sure type is loaded (this will only get loaded on first run):
        Add-Type @"
            using System; 
            using System.Text;
            using System.Runtime.InteropServices; 
            $($Namespace | ForEach-Object {
                "namespace $_ {"
            })
                public class advapi32 {
                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegQueryInfoKey(
                        IntPtr hKey,
                        StringBuilder lpClass,
                        [In, Out] ref UInt32 lpcbClass,
                        UInt32 lpReserved,
                        out UInt32 lpcSubKeys,
                        out UInt32 lpcbMaxSubKeyLen,
                        out UInt32 lpcbMaxClassLen,
                        out UInt32 lpcValues,
                        out UInt32 lpcbMaxValueNameLen,
                        out UInt32 lpcbMaxValueLen,
                        out UInt32 lpcbSecurityDescriptor,
                        out Int64 lpftLastWriteTime
                    );
                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegOpenKeyEx(
                        IntPtr hKey,
                        string lpSubKey,
                        Int32 ulOptions,
                        Int32 samDesired,
                        out IntPtr phkResult
                    );
                    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                    public static extern Int32 RegCloseKey(
                        IntPtr hKey
                    );
                }
            $($Namespace | ForEach-Object { "}" })
"@
    
        # Get a shortcut to the type:    
        $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "ByKey" {
                # Already have the key, no more work to be done :)
            }

            "ByPath" {
                # We need a RegistryKey object (Get-Item should return that)
                $Item = Get-Item -Path $Path -ErrorAction Stop

                # Make sure this is of type [Microsoft.Win32.RegistryKey]
                if ($Item -isnot [Microsoft.Win32.RegistryKey]) {
                    throw "'$Path' is not a path to a registry key!"
                }
                $RegistryKey = $Item
            }
        }

        # Initialize variables that will be populated:
        $ClassLength = 255 # Buffer size (class name is rarely used, and when it is, I've never seen 
                            # it more than 8 characters. Buffer can be increased here, though. 
        $ClassName = New-Object System.Text.StringBuilder $ClassLength  # Will hold the class name
        $LastWriteTime = $null

        # Get a handle to our key via RegOpenKeyEx (PSv3 and higher could use the .Handle property off of registry key):
        $KeyHandle = New-Object IntPtr

        if ($RegistryKey.Name -notmatch "^(?<hive>[^\\]+)\\(?<subkey>.+)$") {
            Write-Error ("'{0}' not a valid registry path!")
            return
        }

        $HiveName = $matches.hive -replace "(^HKEY_|_|:$)", ""  # Get hive in a format that [RegistryHive] enum can handle
        $SubKey = $matches.subkey

        # Get hive. $HiveName should contain a valid MS.Win32.RegistryHive enum, but it will be in all caps. It seems that
        # [enum]::IsDefined is case sensitive, so that won't work. There's an awesome static method [enum]::TryParse, but it
        # appears that it was introduced in .NET 4. So, I'm just wrapping it in a try {} block:
        try {
            $Hive = [Microsoft.Win32.RegistryHive] $HiveName
        }
        catch {
            Write-Error ("Unknown hive: {0} (Registry path: {1})" -f $HiveName, $RegistryKey.Name)
            return  # Exit function or we'll get an error in RegOpenKeyEx call
        }

        Write-Verbose ("Attempting to get handle to '{0}' using RegOpenKeyEx" -f $RegistryKey.Name)
        switch ($RegTools::RegOpenKeyEx(
            $Hive.value__,
            $SubKey,
            0,  # Reserved; should always be 0
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [ref] $KeyHandle
        )) {
            0 { # Success
                # Nothing required for now
                Write-Verbose "  -> Success!"
            }

            default {
                # Unknown error!
                Write-Error ("Error opening handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
            
        switch ($RegTools::RegQueryInfoKey(
            $KeyHandle,
            $ClassName, 
            [ref] $ClassLength, 
            $null,  # Reserved
            [ref] $null, # SubKeyCount
            [ref] $null, # MaxSubKeyNameLength
            [ref] $null, # MaxClassLength
            [ref] $null, # ValueCount
            [ref] $null, # MaxValueNameLength 
            [ref] $null, # MaxValueValueLength 
            [ref] $null, # SecurityDescriptorSize
            [ref] $LastWriteTime
        )) {

            0 { # Success
                $LastWriteTime = [datetime]::FromFileTime($LastWriteTime)

                # Add properties to object and output them to pipeline
                $RegistryKey | 
                    Add-Member -MemberType NoteProperty -Name LastWriteTime -Value $LastWriteTime -Force -PassThru |
                    Add-Member -MemberType NoteProperty -Name ClassName -Value $ClassName.ToString() -Force -PassThru
            }

            122  { # ERROR_INSUFFICIENT_BUFFER (0x7a)
                throw "Class name buffer too small"
                # function could be recalled with a larger buffer, but for
                # now, just exit
            }

            default {
                throw "Unknown error encountered (error code $_)"
            }
        }

        # Closing key:
        Write-Verbose ("Closing handle to '{0}' using RegCloseKey" -f $RegistryKey.Name)
        switch ($RegTools::RegCloseKey($KeyHandle)) {
            0 {
                # Success, no action required
                Write-Verbose "  -> Success!"
            }
            default {
                Write-Error ("Error closing handle to key '{0}': {1}" -f $RegistryKey.Name, $_)
            }
        }
    }
}

#**************************** Main Script Steps Here ************************************

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "Setting registry paths to lookup applications installations for 32bit and 64bit installations" -ForegroundColor Green
#Adding the paths and column headers for the 32bit and 64bit installed apps
$AppPaths = @()
$item = New-Object PSObject
$item | Add-Member -type NoteProperty -Name 'HKU_SID' -Value 'NotApplicable'
$item | Add-Member -type NoteProperty -Name 'HKU_AADObjectID' -Value 'NotApplicable'
$item | Add-Member -type NoteProperty -Name 'RegPath' -Value '32BitPath'
$item | Add-Member -type NoteProperty -Name 'RegLocation' -Value 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$AppPaths += $item
$item = New-Object PSObject
$item | Add-Member -type NoteProperty -Name 'HKU_SID' -Value 'NotApplicable'
$item | Add-Member -type NoteProperty -Name 'HKU_AADObjectID' -Value 'NotApplicable'
$item | Add-Member -type NoteProperty -Name 'RegPath' -Value '64BitPath'
$item | Add-Member -type NoteProperty -Name 'RegLocation' -Value 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$AppPaths += $item

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "Determining registry paths to lookup applications installations under user profiles" -ForegroundColor Green
#Determining applications installed under user profiles and adding to $AppPaths array
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$HKU = Get-ChildItem -Path 'Registry::HKU'
ForEach ($User in $HKU) {
	$UserPath = "Registry::HKU\" + $User.PSChildName + "\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	if (Test-Path -Path $UserPath) {
		$SID = $User.PSChildName
		$AADObjectID = Convert-AzureAdSidToObjectId -SID $SID | Select -ExpandProperty GUID
		$item = New-Object PSObject
		$item | Add-Member -type NoteProperty -Name 'HKU_SID' -Value $SID
		$item | Add-Member -type NoteProperty -Name 'HKU_AADObjectID' -Value $AADObjectID
		$item | Add-Member -type NoteProperty -Name 'RegPath' -Value 'HKU'
		$item | Add-Member -type NoteProperty -Name 'RegLocation' -Value $UserPath
		$AppPaths += $item
	}
}

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "Script will lookup applications installed under the following registry paths" -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
$AppPaths | Select -ExpandProperty RegLocation

$CombinedAppList = @()

ForEach ($AppPath in $AppPaths) {
	$AppListed = Get-ItemProperty $AppPath.RegLocation | Where {$_.UninstallString -ne $NULL}
	$AppListed | Add-Member -NotePropertyName ComputerName -NotePropertyValue $ComputerName
	$AppListed | Add-Member -NotePropertyName DateCollected -NotePropertyValue $DateCollected
	$AppListed | Add-Member -NotePropertyName ComputerSerialNumber -NotePropertyValue $ComputerSerialNumber
	If ($AppPath.RegPath -eq "HKU") {
		$AppListed | Add-Member -type NoteProperty -Name 'HKU_SID' -Value $AppPath.HKU_SID
		$AppListed | Add-Member -type NoteProperty -Name 'HKU_AADObjectID' -Value  $AppPath.HKU_AADObjectID
		$AppListed | Add-Member -type NoteProperty -Name 'RegPath' -Value $AppPath.RegPath
	}
	Else {
		$AppListed | Add-Member -type NoteProperty -Name 'HKU_SID' -Value 'NotApplicable'
		$AppListed | Add-Member -type NoteProperty -Name 'HKU_AADObjectID' -Value 'NotApplicable'
		$AppListed | Add-Member -type NoteProperty -Name 'RegPath' -Value $AppPath.RegPath
	}
	$CombinedAppList += $AppListed
}

ForEach ($App in $CombinedAppList) {
	$RegKeyDate = Get-RegWriteTime -Path $App.PSPath | Select LastWriteTime
	$RegKeyDate = $RegKeyDate.LastWriteTime.ToString()
	$App | Add-Member -NotePropertyName RegKeyLastWriteTime -NotePropertyValue $RegKeyDate
	$RegistryLocation = Get-Item -Path $App.PSPath | Select -ExpandProperty Name
	$App | Add-Member -NotePropertyName RegistryLocation -NotePropertyValue $RegistryLocation
	
	If ($App.InstallDate -notlike $NULL) {
		$InstallDate = $App.InstallDate
		$InstallYear = $InstallDate.SubString(0,4)
		$InstallMonth = $InstallDate.SubString(4,2)
		$InstallDay = $InstallDate.SubString(6,2)
		$InstallDateRegKey = $InstallMonth + "/" + $InstallDay + "/" + $InstallYear
		#$InstallDateRegKey = $InstallDay + "/" + $InstallMonth + "/" + $InstallYear
		$App.InstallDate = $InstallDateRegKey
	}
	ElseIf ($App.InstallDate -like $NULL) {
		$RegKeyDateStripped = $RegKeyDate -replace '^([^ ]+ ).+$','$1'
		$InstallDate = $RegKeyDateStripped
		$InstallYear = $InstallDate.SubString(6,4)
		$InstallMonth = $InstallDate.SubString(3,2)
		$InstallDay = $InstallDate.SubString(0,2)
		$InstallDateRegKey = $InstallMonth + "/" + $InstallDay + "/" + $InstallYear
		$App | Add-Member -NotePropertyName InstallDate -NotePropertyValue $InstallDateRegKey
	}
}

$CombinedAppList = $CombinedAppList | Sort-Object DisplayName | Select-Object ComputerName, DateCollected, ComputerSerialNumber, Publisher, DisplayName, DisplayVersion, InstallDate, SystemComponent, WindowsInstaller, QuietUninstallString, UninstallString, VersionMajor, VersionMinor, DisplayIcon, Comments, HelpLink, EstimatedSize, InstallLocation, HKU_SID, HKU_AADObjectID, RegKeyLastWriteTime, RegPath, RegistryLocation


$NonSysCompAppsCount = ($CombinedAppList | Where {$_.SystemComponent -notlike "1"}).count
$AppCount = $CombinedAppList.count

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "There are $AppCount records to upload to LogAnalytics; $NonSysCompAppsCount of those are listed in add/remove programs" -ForegroundColor Green

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "Creating the object to send to Log Analytics custom logs" -ForegroundColor Green
# Creating the PowerShell object to send to Log Analytics custom logs
$CombinedAppListJSON = $CombinedAppList | ConvertTo-JSON -Depth 10

$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($CombinedAppListJSON))
	LogType    = $LogType 
}

Write-Host "------------------------------------" -ForegroundColor Green
Write-Host "Posting $AppCount records to LogAnalytics" -ForegroundColor Green
Write-Host "------------------------------------" -ForegroundColor Green
Post-LogAnalyticsData @params
	
If($Exit_Status -eq 1)
	{
		EXIT 1
	}
Else
	{
		EXIT 0
	}	
