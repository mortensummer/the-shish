# The SHISH 
This script lists all Virtual Machines in an Azure estate, enables JIT on demand, and then initiates an RDP session to one or multiple virtual machines all in one swift action. 

This script was born out of frustration - a customer only used JIT for their legacy infrastructure, and it was painful navigating and enabling JIT every time access was required to a VM. This script solved that problem until improved networking was introduced. 

## What does the acronym 'SHISH' mean? 
The Supremely Heroic Instance Startup Helper. Named and inspired by a DevOps Engineer who liked kebabs, and all tooling that he created had a kebab-related name.  

## Installation
Subscriptions from Azure are only included if they include the 'SHISHEnabled' tag, and it is set to 'True'. 
It needs the Az PowerShell modules. Does work on PS 5.1, but i've noticed its performs better on PS Core.

## Execution Notes
- The SHISH on first run, gets all the Virtual Machines and caches them locally in %AppData%\TheShish in an XML file. This file is auto-updated every 6 days. 
- On the subsequent executions, The SHISH will read the VM's from the cache for faster execution. 
- It is possible to force-update the cache using the 'UpdateCache' parameter. 
- If a Virtual Machine is off, it will get started (permissions dependant)

## Multi-Select
It is possible to open multiple windows to multiple virtual machines by use of multi-select. Press "ctrl" whilst selecting, or use "Shift" to batch select adjacent VM's. 

## Examples of use
Display all Virtual Machines in an OutGridView. 

```PS> Connect-AzVM.ps1```

Will get all Virtual Machines from Azure (permissions dependant) and store in %AppData%\TheShish\VMsforRDP.xml. 

```PS> Connect-AzVM.ps1 -UpdateCache```

Will display all Virtual Machines in an OutGridView, and set the RDP connection parameters to use a 1024x768 resolution.

```PS> Connect-AzVM.ps1 -RDPResolution -RDPWidth 1024 -RDPHeight 768```

## Limitations
- Cannot double click items in the OutGridView
- Does not list Classic VM's.
- Does not add in rules for NSG’s that do not have JIT enabled. 
- Does not use or allow Bastion hosts.

## Further Notes
There are probably more efficient ways of doing the actions and code in this script, however it was done to solve a very specific problem. In addition, there maybe defects! (As with everyone in this world, I'm still learning)

You are free to modify the script as you see fit - and if there are any improvements that you'd like to share, feel free to make a pull request. 
