##########################################################################################################
##
## Winster v1.0.0
##
## by Fernando B. (fernandobe+git@protonmail.com)
## 6/23/2020
##
## A module for checking common items in Windows OS
## which can then later be compared with something like Pester
## 
## https://github.com/kodaman2/Winster
## 
##########################################################################################################

# Finds and returns a windows registry key
# returns a string
function Get-RegistryKey($regKey, $keyPropertyName)
{
    return (Get-ItemProperty -Path $regKey -Name $keyPropertyName).$keyPropertyName
}

# https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
# Checks whether a path exists
# returns a boolean
function Test-RegistryPath($regKey)
{
    return Test-Path $regKey
}

# Checks whether a key exists
# returns a boolean
function Test-RegistryValue {

    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
    }
    catch {
        return $false
    }

}

# In some rare ocassions two keys need to be compared
# returns a boolean
function Compare-TwoRegistryKey($regKey, $keyPropertyName, $regKey2, $keyPropertyName2, $comparisonValue)
{
    $val = (Get-ItemProperty -Path $regKey -Name $keyPropertyName).$keyPropertyName
    $val2 = (Get-ItemProperty -Path $regKey2 -Name $keyPropertyName2).$keyPropertyName2

    if($val -eq $comparisonValue -and $val2 -eq $comparisonValue)
    {
        return $true
    } else {
        return $false
    }
}

# Test whether stringToMatch exists in a registry key
# useful when we don't know the value of a key but know part of a key
# returns a boolean
function Test-StringInKey($regKey, $keyPropertyName, $stringToMatch)
{
    $val = (Get-ItemProperty -Path $regKey -Name $keyPropertyName).$keyPropertyName

    $grep = $val | Select-String -Pattern $stringToMatch

    if($grep){
        return $true
    } else {
        return $false
    }
}

function Confirm-FolderExists($folderPath)
{
    if(Test-Path $folderPath){
        return $true
    } else {
        return $false
    }
}

# FullPath needs to be the full path to the file, file name can include wildcat
# Examples
# C:\Windows\Temp\somefile.txt
# C:\Windows\Temp\somefile.*
function Confirm-FileExistsLeaf($fullPath)
{
    if(Test-Path $fullPath -PathType Leaf){
        return $true
    } else {
        return $false
    }
}

function Confirm-FileExists($fullPath)
{
    if(Test-Path $fullPath){
        return $true
    } else {
        return $false
    }
}

function Get-RamBytes
{
    # ram
    $memory = Get-WmiObject win32_physicalmemory
    $ram = $memory.Capacity
    $totalMemory = 0

    # if there more than 1 stick
    if($memory.Count -gt 1){
        foreach($stick in $ram){
            #Write-Host($stick)
            $totalMemory += $stick
        }
    } else {
        $totalMemory = $memory.Capacity
    }

    return $totalMemory
}

function Get-NumProcessors
{
    return (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
}

function Get-DiskSize($currentHost, $driveLetter)
{
    return (Get-WmiObject Win32_LogicalDisk -ComputerName $currentHost -Filter "DeviceID='${driveLetter}:'").Size
}

# This is just a quick helper to read json data
function Get-JsonData($configPath)
{
    return Get-Content -Raw -Path $configPath | ConvertFrom-Json
}

# https://exchangepedia.com/2017/11/get-file-or-folder-permissions-using-powershell.html
function Confirm-FolderAccess($folderPath, $CheckUser)
{    
    $Folder = $folderPath
    $permission = (Get-Acl $Folder).Access | ?{$_.IdentityReference -match $CheckUser} | Select IdentityReference,FileSystemRights, AccessControlType

    If ($permission)
    {
        #$permission | % {Write-Host "User $($_.IdentityReference) has '$($_.FileSystemRights)' rights on folder $Folder"}
        # Deny, or Allow
        return $permission.AccessControlType
    }
    Else {
        return $null
    }
}

function Confirm-FolderAccess2 ($folderPath, $userOrGroup, $accesschkToolPath) 
{
    ##https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
    #$accessloc =  $configpath + "\accesschk.exe"
    $accessloc = $accesschkToolPath

    $args ="-accepteula -dq"

    $accesscheck = $accessloc + " " + $userOrGroup + " " + $folderPath + " " + $args

    IF (Test-Path $folderPath) {

        $results = (& invoke-Expression $accesscheck)

        IF ($results -like "Invalid account name:*")  { 
            return "User Account Not exist" 
        }
        IF ($results -eq "No matching objects found." ) {
            return "No Access" 
        }
        IF ($results -eq "RW "+ $folderPath) { 
            return "Read Write Access" 
        }
        IF ($results -eq "R  "+ $folderPath) { 
            return "Read Access" 
        }

    } Else { return "Path Not Found" }
}


function Confirm-ProcessRunning($processName)
{
    $eatonPower = Get-Process $processName -ErrorAction SilentlyContinue

    if($eatonPower){
        return $true
    } else {
        return $false
    }
}

function Confirm-HotFix($patchId)
{
    $patchInfo = Get-HotFix -Id $PatchId -ErrorAction SilentlyContinue
    
    if($patchInfo)
    {
        return $true
    } else {
        return $false
    }
}

function Get-Hosts
{
    $localhosts = @()

    $c = Get-Content $env:SystemRoot\System32\Drivers\etc\hosts

    foreach ($line in $c) {
        $bits = [regex]::Split($line, "\t+")
        if ($bits.count -eq 2) {
            #Write-Host $bits[0] `t`t $bits[1]
            $localhosts += $bits[0]
        }
    }

    return $localhosts
}

function Compare-FileVersion($filepath, $version)
{
    $fileVersion = (Get-Command $filepath).Version

    if ($fileVersion -ge [version]$version){
        return $true
    } else {
        return $false
    }
}

# https://adamtheautomator.com/one-server-port-testing-tool/
function Test-Port ($Port, $Protocol){
	
	# Original function is really for multiple computers, and multiple ports
    # but for unit testing is better to test one machine, one port at a time
    # PS> Test-Port $ComputerName 80 TCP

	process {
        [int]$TcpTimeout = 1000
    	[int]$UdpTimeout = 1000
        # Modification necessary to avoid inputting hostname
        $ComputerName = (Get-WmiObject Win32_ComputerSystem).Name

		foreach ($Computer in $ComputerName) {
			foreach ($Portx in $Port) {
				$Output = @{ 'Computername' = $Computer; 'Port' = $Portx; 'Protocol' = $Protocol; 'Result' = '' }
				Write-Verbose "$($MyInvocation.MyCommand.Name) - Beginning port test on '$Computer' on port '$Protocol<code>:$Portx'"
				if ($Protocol -eq 'TCP') {
					$TcpClient = New-Object System.Net.Sockets.TcpClient
					$Connect = $TcpClient.BeginConnect($Computer, $Portx, $null, $null)
					$Wait = $Connect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)
					if (!$Wait) {
						$TcpClient.Close()
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol</code>:$Portx'"
						$Output.Result = $false
					} else {
						$TcpClient.EndConnect($Connect)
						$TcpClient.Close()
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol<code>:$Portx'"
						$Output.Result = $true
					}
					$TcpClient.Close()
					$TcpClient.Dispose()
				} elseif ($Protocol -eq 'UDP') {
					$UdpClient = New-Object System.Net.Sockets.UdpClient
					$UdpClient.Client.ReceiveTimeout = $UdpTimeout
					$UdpClient.Connect($Computer, $Portx)
					Write-Verbose "$($MyInvocation.MyCommand.Name) - Sending UDP message to computer '$Computer' on port '$Portx'"
					$a = new-object system.text.asciiencoding
					$byte = $a.GetBytes("$(Get-Date)")
					[void]$UdpClient.Send($byte, $byte.length)
					#IPEndPoint object will allow us to read datagrams sent from any source.
					Write-Verbose "$($MyInvocation.MyCommand.Name) - Creating remote endpoint"
					$remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
					try {
						#Blocks until a message returns on this socket from a remote host.
						Write-Verbose "$($MyInvocation.MyCommand.Name) - Waiting for message return"
						$receivebytes = $UdpClient.Receive([ref]$remoteendpoint)
						[string]$returndata = $a.GetString($receivebytes)
						If ($returndata) {
							Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol</code>:$Portx'"
							$Output.Result = $true
						}
					} catch {
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol`:$Portx' with error '$($_.Exception.Message)'"
						$Output.Result = $false
					}
					$UdpClient.Close()
					$UdpClient.Dispose()
				}
				# [pscustomobject]$Output # This prints a result table, which we don't need
                if($Output.Result -eq $true){
                    return $true
                } else {
                    return $false
                }
			}
		}
	}
}

# https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
# This function will search all uninstall keys in two places
# SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall
# SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
# These two are what is in Add Remove Programs in Control Panel
# wmic product get name,version is way too slow 17min~
# function returns true if DisplayVersion is greater than version
# ex: DisplayVersion = 4.11.00
#     version        = 4.10.00
# True
# ex: DisplayVersion = 4.15.00
#     version        = 4.10.00
# True
# ex: DisplayVersion = 4.00.00
#     version        = 4.10.00
# False
function Find-ProgramVersion($programName, $version)
{
    $computerName = $env:COMPUTERNAME
    $uninstallKey = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()
    $programFound = $false

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName)
        {
            $programFound = $true
            if([version]$DisplayVersion -ge [version]$version){
                return $true
            } else {
                return $false
            }
        }
    }

    # Repeat for old unistall path, yeah is duplicated code but don't feel like
    # having to do two functions for now
    $uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName)
        {
            #Write-Host $DisplayName $DisplayVersion
            $programFound = $true
            if([version]$DisplayVersion -ge [version]$version){
                return $true
            } else {
                return $false
            }
        }
    }

    if($programFound -eq $false){
        return $false
    }
}

# Exclude a certain string
function Find-ProgramVersionExclude($programName, $version, $excludeString)
{
    $computerName = $env:COMPUTERNAME
    $uninstallKey = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()
    $programFound = $false

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName | Select-String -Pattern $excludeString -NotMatch)
        {
            $programFound = $true
            if([version]$DisplayVersion -ge [version]$version){
                return $true
            } else {
                return $false
            }
        }
    }

    # Repeat for old unistall path, yeah is duplicated code but don't feel like
    # having to do two functions for now
    $uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName | Select-String -Pattern $excludeString -NotMatch)
        {
            #Write-Host $DisplayName $DisplayVersion
            $programFound = $true
            if([version]$DisplayVersion -ge [version]$version){
                return $true
            } else {
                return $false
            }
        }
    }

    if($programFound -eq $false){
        return $false
    }
}

# This funtion exists mainly thanks for rslinx
# which has an unusual version string and makes version casting difficult
# 4.11.00 CPR 9 SR 11.0
function Find-ProgramVersionGrep($programName, $version)
{
    $computerName = $env:COMPUTERNAME
    $uninstallKey = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()
    $programFound = $false

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName)
        {
            $programFound = $true
            if($DisplayVersion | Select-String $version){
                return $true
            } else {
                return $false
            }
        }
    }

    # Repeat for old unistall path, yeah is duplicated code but don't feel like
    # having to do two functions for now
    $uninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computerName)
    $regkey = $reg.OpenSubKey($uninstallKey)
    $subkeys = $regkey.GetSubKeyNames()

    foreach($key in $subkeys){
    
        $thiskey = $uninstallKey+"\\"+$key
        $thissubkey = $reg.OpenSubKey($thiskey)
        $DisplayName = $thissubkey.GetValue("DisplayName")
        $DisplayVersion = $thissubkey.GetValue("DisplayVersion")
        $Publisher = $thissubkey.GetValue("Publisher")

    
        if($DisplayName | Select-String -Pattern $programName)
        {
            $programFound = $true
            if($DisplayVersion | Select-String $version){
                return $true
            } else {
                return $false
            }
        }
    }

    if($programFound -eq $false){
        return $false
    }
}

function Request-Command ($cmd) {
    return Invoke-Expression $cmd
}

# returns 1 or 0
function Test-WinActivation() {
    return (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } ).LicenseStatus
}

# this function checks whether a windows feature is enabled or disable and returns a boolean
# compatible with Windows Server 2016, and Windows 10
# enabled = true, disabled = false
function Confirm-WindowsFeature($feature) {
   
    if(Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue){
        if((Get-WindowsFeature $feature).InstallState -eq "Installed"){
            return $true
        } else {
            #Write-Host $feature "Not Installed"
            return $false
        }
    }

    if(Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue){
        if((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -eq "Enabled"){
            return $true
        } else {
            #Write-Host $feature "Not Installed"
            return $false
        }
    }
}

# https://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/2376
function Convert-Size {            
    [cmdletbinding()]            
    param(            
        [validateset("Bytes","KB","MB","GB","TB")]            
        [string]$From,            
        [validateset("Bytes","KB","MB","GB","TB")]            
        [string]$To,            
        [Parameter(Mandatory=$true)]            
        [double]$Value,            
        [int]$Precision = 4            
    )            
    switch($From) {            
        "Bytes" {$value = $Value }            
        "KB" {$value = $Value * 1024 }            
        "MB" {$value = $Value * 1024 * 1024}            
        "GB" {$value = $Value * 1024 * 1024 * 1024}            
        "TB" {$value = $Value * 1024 * 1024 * 1024 * 1024}            
    }            
            
    switch ($To) {            
        "Bytes" {return $value}            
        "KB" {$Value = $Value/1KB}            
        "MB" {$Value = $Value/1MB}            
        "GB" {$Value = $Value/1GB}            
        "TB" {$Value = $Value/1TB}            
            
    }            
            
    return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)            
            
} 
