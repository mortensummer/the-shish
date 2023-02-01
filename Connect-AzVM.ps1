<#
.SYNOPSIS
Connect-AzVM.ps1 lists all Virtual Machines in the Azure estate, enables JIT on demand, and then initiates an RDP session. 

.DESCRIPTION
Connect-AzVM.ps1 on first run, gets all the Virtual Machines and caches them locally in %AppData%\TheShish in an XML file.
Subscriptions from Azure are only included if they include the 'SHISHEnabled' tag, and it is set to 'True'.
On the subsequent executions, Connect-AzVM.ps1 will read the VM's from the cache for faster execution. It is possible to 
update the cache using the 'UpdateCache' parameter. Requires the AZ Module. 

.INPUTS
None. 

.OUTPUTS
OutGridView of Virtual Machines for selection. 

.EXAMPLE
PS> Connect-AzVM.ps1
Will display all Virtual Machines in an OutGridView. 

PS> Connect-AzVM.ps1 -UpdateCache
Will get all Virtual Machines from Azure (permissions dependant) and store in %AppData%\TheShish\VMsforRDP.xml. 

PS> Connect-AzVM.ps1 -RDPResolution -RDPWidth 1024 -RDPHeight 768
Will display all Virtual Machines in an OutGridView, and set the RDP connection parameters to use a 1024x768 resolution.

.PARAMETER UpdateCache
Instruct script to update the local cache of Virtual Machines. 

.PARAMETER RDPResolution
Switch to define the width and height of the RDP session. Requires RDPWidth and RDPHeight to be populated.  

.PARAMETER RDPWidth
Defines the width of the RDP session.

.PARAMETER RDPHeight
Defines the height of the RDP session.

.NOTES
Initial Configuration:
 - Add a Tag onto desired subscriptions called 'SHISHEnabled' and set to "True". Without this tag, the subscription will not be searched for VM's. 

Limitations:
 - Does not list Classic VM's.
 - Does not work on VM's that do not have JIT enabled. 
 - Does not use or allow Bastion hosts. 
#>

[CmdletBinding(DefaultParameterSetName='None')]
param (
    [Parameter(Position=0,ParameterSetName='None')][Switch]$UpdateCache,
    [Parameter(Position=1,ParameterSetName='Resolution')][Switch]$RDPResolution,
    [Parameter(ParameterSetName='Resolution',Mandatory=$True)][Int]$RDPWidth,
    [Parameter(ParameterSetName='Resolution',Mandatory=$True)][Int]$RDPHeight
)

## Cache Settings #######################################################################
$StaleCache = 6                             # Days until the cache is treated as stale  #
$AppPath = "$ENV:APPDATA\TheShish"          # Cache location                            #
$ConfigXML = "$AppPath\VMsforRDP.xml"       # Cache name                                #
#########################################################################################

Clear-Host
$Welcome = @"
####################################################                                                        
 _____ _            _____ _   _ _____ _____ _   _ 
|_   _| |          /  ___| | | |_   _/  ___| | | |
  | | | |__   ___  \ ``--.| |_| | | | \ ``--.| |_| |
  | | | '_ \ / _ \  ``--. \  _  | | |  ``--. \  _  |
  | | | | | |  __/ /\__/ / | | |_| |_/\__/ / | | |
  \_/ |_| |_|\___| \____/\_| |_/\___/\____/\_| |_/

###################################################
   Supremely Heroic Instance Startup Helper v1.2       
###################################################
"@
Write-Host $Welcome

# Export all VMs found into an XML file for caching and speed purposes
function Export-AzVirtualMachines{
    Remove-Item $ConfigXML -Force -ErrorAction SilentlyContinue | Out-Null
    $AllVMsForJIT = Get-AzVirtualMachines ((Get-AzSubscription)  | Where-Object {$_.Tags.SHISHEnabled -eq "True"})
    try{
        Export-Clixml -InputObject $AllVMsForJIT $ConfigXML -Force
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Error "Could not export to '$ConfigXML'. Error: $ErrorMessage"
        Break
    }
    Return $AllVMsForJIT
}

# Import all VMs found in the XML file 
function Import-AzVirtualMachines{
    try{
        $AllVMsForJIT = Import-Clixml -path $ConfigXML
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Error "Could not import from to '$ConfigXML'. Error: $ErrorMessage"
        Break
    }
    Return $AllVMsForJIT
}

function Get-AssociatedNSGRules($theVM){
    $VMObj = Get-AzVM -Name $TheVM.Name -ResourceGroupName $TheVM.ResourceGroupName
    $NSGNotOnVM = $False
    try{
        $NSGName = ((Get-AzNetworkInterface -ResourceId ($VMObj).NetworkProfile.NetworkInterfaces.Id -ErrorAction Stop).NetworkSecurityGroup).Id.Split('/')[-1]
        $NSGRules = (Get-AzNetworkSecurityGroup -Name $NSGName).SecurityRules
        $NSGNotOnVM = $False
    }
    Catch{
        $NSGNotOnVM = $True
    }
    If($NSGNotOnVM){
        # Get VNic and associated info
        $vmnic = ($VMObj.NetworkProfile.NetworkInterfaces.id).Split('/')[-1]
        $vmnicinfo = Get-AzNetworkInterface -Name $vmnic

        # Get vNet
        $subnetid = $vmnicinfo.IpConfigurations.subnet.id
        $NSGs = Get-AzNetworkSecurityGroup | Where-object {$_.Subnets.Id -eq $subnetid}
        $NSGRules = ($NSGs).SecurityRules
    }
    Return $NSGRules
}

# Wait for the VM to be started before proceeding
function Wait-AzVM($Name, $ResourceGroupName){
    While((Get-AzVM -Name $name -ResourceGroupName $ResourceGroupName -Status).Statuses[1].DisplayStatus -ne 'vm running'){
        Start-Sleep -Seconds 1
        Write-Host "$Name not started...waiting..."
    }
}

# Get the Public IP address of the Azure Virtual Machine
function Get-AzPublicIpAddress($VMname, $ResourceGroupName) {
    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMname
    try{
        $nic = $vm.NetworkProfile.NetworkInterfaces[0].Id.Split('/') | Select-Object -Last 1
        $publicIpName =  (Get-AzNetworkInterface -ResourceGroupName $VM.ResourceGroupName -Name $nic -ErrorAction Stop).IpConfigurations.PublicIpAddress.Id.Split('/') | Select-Object -Last 1
        $publicIpAddress = (Get-AzPublicIpAddress -ResourceGroupName $VM.ResourceGroupName -Name $publicIpName -ErrorAction Stop).IpAddress
        $fqdn = (Get-AzPublicIpAddress -ResourceGroupName $VM.ResourceGroupName -Name $publicIpName -ErrorAction SilentlyContinue).DnsSettings.Fqdn
    }
    Catch{
        $ErrorMessage = $_.Exception.Message
        Write-Warning "Could not get internet facing address $($TheVM.Name). Error: $ErrorMessage"
    }

    If($fqdn){
        Return $fqdn
    }
    else{
        Return $publicIpAddress
    }
    
}

# Get all Virtual Machines from Subscriptions
function Get-AzVirtualMachines($subscriptions){
    $VMsForJIT = @()    
    Foreach ($Sub in $Subscriptions){
        Write-Host "Getting VM's from Subscription '$($Sub.Name)'..." 
        $Context = Set-AzContext -TenantId $Sub.TenantId -SubscriptionId $Sub.Id -Force
    
        $VMCloudDefenderPricingTier = (Get-AzSecurityPricing -Name virtualMachines -ErrorAction SilentlyContinue).PricingTier
        If($VMCloudDefenderPricingTier -eq 'Standard'){
            $JITEnabled = $True
        }elseif ($VMCloudDefenderPricingTier -eq 'Free'){
            $JITEnabled = $False
        }

        $AzVMs = Get-AzResource -ResourceType Microsoft.Compute/virtualMachines
        foreach ($vm in $AzVMs){
            Write-Verbose "Found '$($vm.Name)'" 
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name VM_Name -Value $vm.Name
            $Obj | Add-Member -MemberType NoteProperty -Name VM_ResGroup -Value $vm.ResourceGroupName
            $Obj | Add-Member -MemberType NoteProperty -Name Subscription -Value $Sub.Name
            $Obj | Add-Member -MemberType NoteProperty -Name JITEnabled -Value $JITEnabled
            $Obj | Add-Member -MemberType NoteProperty -Name Location -Value $vm.Location
            $Obj | Add-Member -MemberType NoteProperty -Name SubscriptionID -Value $Sub.Id
            $VMsForJIT += $obj
        } 
    }
    Return $VMsForJIT
}

# Start the RDP session to the Virtual Machine, including initiating the JIT policy
function Start-AzVirtualMachine ([bool]$JITStatus){
    Write-Host "Checking if the VM is running..."
    try{
        $VMStatus = Get-AzVM -Name $TheVM.Name -ResourceGroupName $TheVM.ResourceGroupName -Status -ErrorAction Stop
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        Write-Verbose "could not get VM status from $($TheVM.name): $ErrorMessage"
    }

    If($($VMStatus.Statuses[1].DisplayStatus) -ne 'VM running'){
        try{
            Write-Host "Starting $($TheVM.Name): Please be patient..."
            $TheVM | Start-AzVM -ErrorAction Stop
            Wait-AzVM -Name $TheVM.Name -ResourceGroupName $TheVM.ResourceGroupName
        }
        catch{
            $ErrorMessage = $_.Exception.Message
            Write-Warning "Could not start $($TheVM.Name). Error: $ErrorMessage"
            Break
        }
    }else{
        Write-Verbose "$($TheVM.Name) is already started." 
    }

    $MyIP = (Invoke-WebRequest -uri "https://ifconfig.me/ip").Content
    Write-Host "Your external IP address is`: $($MyIP)"
    
    # TODO - Change to try/catch 
    $IPAddress = Get-AzPublicIpAddress $TheVM.Name $TheVM.ResourceGroupName
    Write-Host "'$($TheVM.Name)' external address is`: $($IPAddress)"

    $VM = Get-AzVM -Name $TheVM.Name -ResourceGroupName $TheVM.ResourceGroupName
    $IPConfig = $VM.NetworkProfile.NetworkInterfaces.Id.Split("/") | Select-Object -Last 1
    $PrivateIP = (Get-AzNetworkInterface -Name $IPConfig).IpConfigurations.PrivateIPAddress

    Write-Host "Checking the Network Security group..."
    $NSGRules = Get-AssociatedNSGRules $TheVM
    $RDPRule = $NSGRules | Where-Object {($_.DestinationAddressPrefix -contains $PrivateIP) -and ($_.DestinationPortRange -contains '3389') -and ($_.SourceAddressPrefix -contains $MyIP) -and ($_.Access -eq 'Allow')}   

    If($RDPRule){
        Write-Host "Boom! NSG Rule already exists for your IP Address. No need to request access."
        $RDPRuleExists = $True
    }else{
        If($JITStatus){
            # Create Just-In-Time Access Policy
            $JITPolicy = (@{
                id = $TheVM.ResourceId; 
                ports=(@{
                    number=3389;
                    endTimeUtc=($(Get-Date).ToUniversalTime()).AddHours(3);
                    allowedSourceAddressPrefix=@($MyIP)
                })
            })
            $ActivationVM = @($JITPolicy)
            
            Write-Host "Darn it. Need to request Just-In-Time Access..."
            Try{
                $command = Start-AzJitNetworkAccessPolicy -ResourceGroupName $($TheVM.ResourceGroupName) -Location $TheVM.Location -Name "default" -VirtualMachine $ActivationVM -ErrorAction Stop
                $commandoutput = $command | ConvertTo-Json -Depth 10
                Write-Verbose $commandoutput
                $JITPolicyEnabled = $True
            }
            Catch{
                $ErrorMessage = $_.Exception.Message
                Write-Warning "Exiting. Could not create JIT Policy for $($TheVM.Name). Error: $ErrorMessage"
                $JITPolicyEnabled = $False
            }

            If($JITPolicyEnabled){
                If($IPAddress){
                    Write-Host "Waiting for JIT to take effect." -NoNewline
                    do {
                        Write-Host "." -NoNewline
                    }
                    until ((Test-Port $IPAddress 3389).PortOpened)
                    $RDPRuleExists = $True
                }else{
                    Write-Output "Not starting RDP session - No public IP address for $($TheVM.Name)"
                }
            }
        }else{
            Write-Warning "Sorry, there isn't a rule in the NSG for your IP Address. You'll have to add this manually."
            $RDPRuleExists = $False
        }
    }

    If($RDPRuleExists){
        If($RDPResolution.IsPresent){
            $arguments = "/v:$IPAddress /w:$RDPWidth /h:$RDPHeight"
        }else{
            $arguments = "/v:$IPAddress"
        }
    
        Try{
            Write-Host "`nSpawning Microsoft Remote Desktop Client..."
            Write-Host "Executed: 'mstsc $arguments'"
    
            $GoProcess = Start-Process -FilePath "mstsc.exe" -ArgumentList $arguments -PassThru
        }
        catch{
            Write-Warning "Could not start RDP session to '$($TheVM.Name)@$IPaddress'"
        }
    }
}

# Credit to https://copdips.com/2019/09/fast-tcp-port-check-in-powershell.html
# Using test-netconnection was too slow as it does an ICMP ping first (which will always fail with Azure as ICMP is not allowed)
function Test-Port {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, HelpMessage = 'Could be suffixed by :Port')]
        [String[]]$ComputerName,

        [Parameter(HelpMessage = 'Will be ignored if the port is given in the param ComputerName')]
        [Int]$Port = 3389,

        [Parameter(HelpMessage = 'Timeout in millisecond. Increase the value if you want to test Internet resources.')]
        [Int]$Timeout = 1000
    )

    begin {
        $result = [System.Collections.ArrayList]::new()
    }

    process {
        foreach ($originalComputerName in $ComputerName) {
            $remoteInfo = $originalComputerName.Split(":")
            if ($remoteInfo.count -eq 1) {
                # In case $ComputerName in the form of 'host'
                $remoteHostname = $originalComputerName
                $remotePort = $Port
            } elseif ($remoteInfo.count -eq 2) {
                # In case $ComputerName in the form of 'host:port',
                # we often get host and port to check in this form.
                $remoteHostname = $remoteInfo[0]
                $remotePort = $remoteInfo[1]
            } else {
                $msg = "Got unknown format for the parameter ComputerName: " `
                    + "[$originalComputerName]. " `
                    + "The allowed formats is [hostname] or [hostname:port]."
                Write-Error $msg
                return
            }

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $portOpened = $tcpClient.ConnectAsync($remoteHostname, $remotePort).Wait($Timeout)

            $null = $result.Add([PSCustomObject]@{
                RemoteHostname       = $remoteHostname
                RemotePort           = $remotePort
                PortOpened           = $portOpened
                TimeoutInMillisecond = $Timeout
                SourceHostname       = $env:COMPUTERNAME
                OriginalComputerName = $originalComputerName
                })
        }
    }

    end {
        return $result
    }
}

#########################################
#### Script Start.                   ####
#########################################

Write-Host "`nChecking if 'AZ' Module is installed..."
if (Get-Module -Name Az -ListAvailable) {
    Write-Host "AZ module found..."
} 
else {
    Write-Host "Installing 'AZ' Modules..."
    Install-Module Az -Scope CurrentUser #-Force
}

Write-Host "Getting Azure context (will prompt for authentication if not already)..."
$Context = Get-AzContext
If(!($Context.Account)){Connect-AzAccount}

If (!(Test-Path($AppPath))){New-Item -ItemType Directory $AppPath | Out-null}

If($UpdateCache.IsPresent){
    $AllVMsForJIT = Export-AzVirtualMachines
    Write-Host "RDP cache updated."
}

$ConfigXMLLastUpdate = (Get-ChildItem $ConfigXML -ErrorAction SilentlyContinue).LastWriteTime
If ($ConfigXMLLastUpdate){
    $TimeDiff = $(Get-Date) - $ConfigXMLLastUpdate
    If($TimeDiff.TotalDays -gt $StaleCache){
        Write-Host "RDP cache is stale, updating it..."
        $AllVMsForJIT = Export-AzVirtualMachines
    }
}
else{
    Write-Host "Cache doesnt exist. Creating it..."
    $AllVMsForJIT = Export-AzVirtualMachines
}

If(Test-Path $ConfigXML){
    $AllVMsForJIT = Import-AzVirtualMachines
}else{
    $AllVMsForJIT = Export-AzVirtualMachines
} 

Write-Host "Outputting VM's to a pretty grid..."
$SelectedVM = $AllVMsForJIT | Sort-Object Subscription, VM_Name | Out-GridView -Title "Which VM do you want to connect to?"  -PassThru

If ($SelectedVM){
    Foreach ($Vm in $SelectedVM){
        Write-Host "`Nice choice! You selected $($VM.VM_Name). Lets set the Azure Context..."
        Set-AzContext -SubscriptionID $Vm.SubscriptionID | out-Null
        $TheVM = Get-AzResource -ResourceGroupName $Vm.VM_ResGroup -Name $Vm.VM_Name -ResourceType "Microsoft.Compute/virtualMachines"
        $JITStatus = $VM.JITEnabled
        Start-AzVirtualMachine $JITStatus
    }

}else{
    Write-Host "Pressed Cancel. Bye."
}