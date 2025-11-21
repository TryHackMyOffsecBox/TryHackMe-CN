---
sidebar_position: 1
---

# Windows PowerShell

## Task 1 Introduction

Ahoy there! If you’re here, you’ve either heard whispers of the marvels of PowerShell and want to discover more, or you’ve sailed over from the first room of the Command Line module—[Windows Command Line](Windows%20Command%20Line.md). Either way, you’re about to embark on a journey to discover the marvels of this powerful shell, learning how to use it to uncover the secrets of any Windows system. Avast, then—on board!

### Learning Objectives

This is the second room in the Command Line module. It is an introductory room to PowerShell, the second—only historically—command-line utility built for the Windows operating system.

- Learn what PowerShell is and its capabilities.
- Understand the basic structure of PowerShell’s language.
- Learn and run some basic PowerShell commands.
- Understand PowerShell’s many applications in the cyber security industry.

### Room Prerequisites

Before approaching this room, it’s recommended that you have understood the concepts in the Windows and AD Fundamentals module and the Windows Command Line room.

:::info Answer the questions below

<details>

<summary> Raise the anchor, hoist the sails—it's time to set sail! </summary>

```plaintext
No answer needed
```

</details>

:::

## Task 2 What Is PowerShell

From the official Microsoft [page](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.4): “PowerShell is a cross-platform task automation solution made up of a command-line shell, a scripting language, and a configuration management framework.”

PowerShell is a powerful tool from Microsoft designed for task automation and configuration management. It combines a command-line interface and a scripting language built on the .NET framework. Unlike older text-based command-line tools, PowerShell is object-oriented, which means it can handle complex data types and interact with system components more effectively. Initially exclusive to Windows, PowerShell has lately expanded to support macOS and Linux, making it a versatile option for IT professionals across different operating systems.

### A Brief History of PowerShell

PowerShell was developed to overcome the limitations of existing command-line tools and scripting environments in Windows. In the early 2000s, as Windows was increasingly used in complex enterprise environments, traditional tools like `cmd.exe` and batch files fell short in automating and managing these systems. Microsoft needed a tool that could handle more sophisticated administrative tasks and interact with Windows’ modern APIs.

Jeffrey Snover, a Microsoft engineer, realised that Windows and Unix handled system operations differently—Windows used structured data and APIs, while Unix treated everything as text files. This difference made porting Unix tools to Windows impractical. Snover’s solution was to develop an object-oriented approach, combining scripting simplicity with the power of the .NET framework. Released in 2006, PowerShell allowed administrators to automate tasks more effectively by manipulating objects, offering deeper integration with Windows systems.

As IT environments evolved to include various operating systems, the need for a versatile automation tool grew. In 2016, Microsoft responded by releasing PowerShell Core, an open-source and cross-platform version that runs on Windows, macOS, and Linux.

### The Power in PowerShell

To fully grasp the power of PowerShell, we first need to understand what an **object** is in this context.

In programming, an **object** represents an item with **properties** (characteristics) and **methods** (actions). For example, a `car` object might have properties like `Color`, `Model`, and `FuelLevel`, and methods like `Drive()`, `HonkHorn()`, and `Refuel()`.

Similarly, in PowerShell, objects are fundamental units that encapsulate data and functionality, making it easier to manage and manipulate information. An object in PowerShell can contain file names, usernames or sizes as data (**properties**), and carry functions (**methods**) such as copying a file or stopping a process.

The traditional Command Shell’s basic commands are text-based, meaning they process and output data as plain text. Instead, when a **cmdlet** (pronounced command-let) is run in PowerShell, it returns objects that retain their properties and methods. This allows for more powerful and flexible data manipulation since these objects do not require additional parsing of text.

We will explore more about PowerShell’s cmdlets and their capabilities in the upcoming sections.

:::info Answer the questions below

<details>

<summary> What do we call the advanced approach used to develop PowerShell? </summary>

```plaintext
object-oriented
```

</details>

:::

## Task 3 PowerShell Basics

### Launching PowerShell

PowerShell can be launched in several ways, depending on your needs and environment. If you are working on a Windows system from the graphical interface (GUI), these are some of the possible ways to launch it:

- **Start Menu**: Type `powershell` in the Windows Start Menu search bar, then click on `Windows PowerShell` or `PowerShell` from the results.
- **Run Dialog**: Press `Win + R` to open the `Run` dialog, type `powershell`, and hit `Enter`.
- **File Explorer**: Navigate to any folder, then type `powershell` in the address bar, and press `Enter`. This opens PowerShell in that specific directory.
- **Task Manager**: Open the Task Manager, go to `File > Run new task`, type `powershell`, and press `Enter`.

Alternatively, PowerShell can be launched from a Command Prompt (`cmd.exe`) by typing `powershell`, and pressing `Enter`.

In our case, where we only have access to the target VM’s Command Prompt, this is the method we’ll use.

```powershell title="Terminal"
captain@THEBLACKPEARL C:\Users\captain>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\captain> 
```

After PowerShell has launched, we’re presented with a `PS` (which stands for `PowerShell`) prompt in the current working directory.

### Basic Syntax: Verb-Noun

As previously mentioned, PowerShell commands are known as `cmdlets` (pronounced `command-lets`). They are much more powerful than the traditional Windows commands and allow for more advanced data manipulation.

Cmdlets follow a consistent `Verb-Noun` naming convention. This structure makes it easy to understand what each cmdlet does. The `Verb` describes the action, and the `Noun` specifies the object on which action is performed. For example:

- `Get-Content`: Retrieves (gets) the content of a file and displays it in the console.
- `Set-Location`: Changes (sets) the current working directory.

### Basic Cmdlets

To list all available cmdlets, functions, aliases, and scripts that can be executed in the current PowerShell session, we can use `Get-Command`. It’s an essential tool for discovering what commands one can use.

```powershell title="Terminal"
PS C:\Users\captain> Get-Command

CommandType     Name                                               Version    Source 
-----------     ----                                               -------    ------ 

Alias           Add-AppPackage                                     2.0.1.0    Appx
Alias           Add-AppPackageVolume                               2.0.1.0    Appx
Alias           Add-AppProvisionedPackage                          3.0        Dism
[...]
Function        A:
Function        Add-BCDataCacheExtension                           1.0.0.0    BranchCache
Function        Add-DnsClientDohServerAddress                      1.0.0.0    DnsClient
[...]
Cmdlet          Add-AppxPackage                                    2.0.1.0    Appx
Cmdlet          Add-AppxProvisionedPackage                         3.0        Dism
Cmdlet          Add-AppxVolume                                     2.0.1.0    Appx
[...]
```

For each `CommandInfo` object retrieved by the cmdlet, some essential information (properties) is displayed on the console. It’s possible to filter the list of commands based on displayed property values. For example, if we want to display only the available commands of type “function”, we can use `-CommandType "Function"`, as shown below:

```powershell title="Terminal"
PS C:\Users\captain> Get-Command -CommandType "Function"

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        A:
Function        Add-BCDataCacheExtension                           1.0.0.0    BranchCache
Function        Add-DnsClientDohServerAddress                      1.0.0.0    DnsClient
Function        Add-DnsClientNrptRule                              1.0.0.0    DnsClient
[...]
```

We will learn more efficient ways to filter output from cmdlets in the upcoming tasks.

Another essential cmdlet to keep in our tool belt is `Get-Help`: it provides detailed information about cmdlets, including usage, parameters, and examples. It’s the go-to cmdlet for learning how to use PowerShell commands.

```powershell title="Terminal"
PS C:\Users\captain> Get-Help Get-Date

NAME
    Get-Date

SYNOPSIS
    Gets the current date and time.

SYNTAX
    Get-Date [[-Date] <System.DateTime>] [-Day <System.Int32>] [-DisplayHint {Date | Time | DateTime}] [-Format <System.String>] [-Hour <System.Int32>] [-Millisecond <System.Int32>] [-Minute <System.Int32>] [-Month <System.Int32>] [-Second <System.Int32>] [-Year <System.Int32>] [<CommonParameters>]

    Get-Date [[-Date] <System.DateTime>] [-Day <System.Int32>] [-DisplayHint {Date | Time | DateTime}] [-Hour <System.Int32>] [-Millisecond <System.Int32>] [-Minute <System.Int32>] [-Month <System.Int32>] [-Second <System.Int32>] [-UFormat <System.String>] [-Year <System.Int32>] [<CommonParameters>]

DESCRIPTION
        The `Get-Date` cmdlet gets a DateTime object that represents the current date or a date that you specify. `Get-Date` can format the date and time in several .NET and UNIX formats. You can use `Get-Date` to generate a date or time character string, and then send the string to other cmdlets or programs.
        
        `Get-Date` uses the current culture settings of the operating system to determine how the output is formatted. To view your computer's settings, use `(Get-Culture).DateTimeFormat`.

RELATED LINKS
    Online Version: https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-date?view=powershell-5.1&WT.mc_id=ps-gethelp
    ForEach-Object
    Get-Culture
    Get-Member
    New-Item
    New-TimeSpan
    Set-Date
    Set-Culture xref:International.Set-Culture

REMARKS
    To see the examples, type: "get-help Get-Date -examples".
    For more information, type: "get-help Get-Date -detailed".
    For technical information, type: "get-help Get-Date -full".
    For online help, type: "get-help Get-Date -online".
```

As shown in the results above, `Get-Help` informs us that we can retrieve other useful information about a cmdlet by appending some options to the basic syntax. For example, by appending `-examples` to the command displayed above, we will be shown a list of common ways in which the chosen cmdlet can be used.

To make the transition easier for IT professionals, PowerShell includes aliases —which are shortcuts or alternative names for cmdlets— for many traditional Windows commands. Indispensable for users already familiar with other command-line tools, `Get-Alias` lists all aliases available. For example, `dir` is an alias for `Get-ChildItem`, and `cd` is an alias for `Set-Location`.

```powershell title="Terminal"
PS C:\Users\captain> Get-Alias

CommandType     Name                                               Version    Source 
-----------     ----                                               -------    ------
Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           ac -> Add-Content
Alias           asnp -> Add-PSSnapin
Alias           cat -> Get-Content
Alias           cd -> Set-Location
Alias           CFS -> ConvertFrom-String                          3.1.0.0    Microsoft.PowerShell.Utility
Alias           chdir -> Set-Location 
Alias           clc -> Clear-Content
Alias           clear -> Clear-Host
[...]
```

### Where to Find and Download Cmdlets

Another powerful feature of PowerShell is the possibility of extending its functionality by downloading additional cmdlets from online repositories.

**NOTE**: Please note that the cmdlets listed in this section require a working internet connection to query online repositories. The attached machine doesn't have access to the internet, therefore these commands won't work in this environment.

To search for modules (collections of cmdlets) in online repositories like the PowerShell Gallery, we can use `Find-Module`. Sometimes, if we don’t know the exact name of the module, it can be useful to search for modules with a similar name. We can achieve this by filtering the `Name` property and appending a wildcard (`*`) to the module’s partial name, using the following standard PowerShell syntax: `Cmdlet -Property "pattern*"`.

```powershell title="Terminal"
PS C:\Users\captain> Find-Module -Name "PowerShell*"   

Version    Name                                Repository           Description 
-------    ----                                ----------           ----------- 
0.4.7      powershell-yaml                     PSGallery            Powershell module for serializing and deserializing YAML

2.2.5      PowerShellGet                       PSGallery            PowerShell module with commands for discovering, installing, updating and publishing the PowerShell artifacts like Modules, DSC Resources, Role Capabilities and Scripts.                                                   
1.0.80.0   PowerShell.Module.InvokeWinGet      PSGallery            Module to Invoke WinGet and parse the output in PSOjects

0.17.0     PowerShellForGitHub                 PSGallery            PowerShell wrapper for GitHub API  
```

Once identified, the modules can be downloaded and installed from the repository with `Install-Module`, making new cmdlets contained in the module available for use.

```powershell title="Terminal"
PS C:\Users\captain> Install-Module -Name "PowerShellGet"

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): 
```

With these essential tools in our belt, we can now start exploring PowerShell’s capabilities.

:::info Answer the questions below

<details>

<summary> How would you retrieve a list of commands that **start with** the verb `Remove`? [for the sake of this question, avoid the use of quotes (" or ') in your answer] </summary>

```plaintext
Get-Command -Name Remove*
```

</details>

<details>

<summary> What cmdlet has its traditional counterpart `echo` as an alias? </summary>

```plaintext
Write-Output
```

</details>

<details>

<summary> What is the command to retrieve some example usage for the cmdlet `New-LocalUser`? </summary>

```plaintext
Get-Help New-LocalUser -examples
```

</details>

:::

## Task 4 Navigating the File System and Working with Files

PowerShell provides a range of cmdlets for navigating the file system and managing files, many of which have counterparts in the traditional Windows CLI.

Similar to the `dir` command in Command Prompt (or `ls` in Unix-like systems), `Get-ChildItem` lists the files and directories in a location specified with the `-Path` parameter. It can be used to explore directories and view their contents. If no `Path` is specified, the cmdlet will display the content of the current working directory.

```powershell title="Terminal"
PS C:\Users\captain> Get-ChildItem 

    Directory: C:\Users\captain

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---          5/8/2021   9:15 AM                Desktop
d-r---          9/4/2024  10:58 AM                Documents
d-r---          5/8/2021   9:15 AM                Downloads
d-r---          5/8/2021   9:15 AM                Favorites
d-r---          5/8/2021   9:15 AM                Links
d-r---          5/8/2021   9:15 AM                Music
d-r---          5/8/2021   9:15 AM                Pictures
d-----          5/8/2021   9:15 AM                Saved Games
d-r---          5/8/2021   9:15 AM                Videos
```

To navigate to a different directory, we can use the `Set-Location` cmdlet. It changes the current directory, bringing us to the specified path, akin to the `cd` command in Command Prompt.

```powershell title="Terminal"
PS C:\Users\captain> Set-Location -Path ".\Documents"
PS C:\Users\captain\Documents> 
```

While the traditional Windows CLI uses separate commands to create and manage different items like directories and files, PowerShell simplifies this process by providing a single set of cmdlets to handle the creation and management of both files and directories.

To create an item in PowerShell, we can use `New-Item`. We will need to specify the path of the item and its type (whether it is a file or a directory).

```powershell title="Terminal"
PS C:\Users\captain\Documents> New-Item -Path ".\captain-cabin\captain-wardrobe" -ItemType "Directory"

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          9/4/2024  12:20 PM                captain-wardrobe

PS C:\Users\captain\Documents> New-Item -Path ".\captain-cabin\captain-wardrobe\captain-boots.txt" -ItemType "File"     

    Directory: C:\Users\captain\Documents\captain-cabin\captain-wardrobe

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  11:46 AM              0 captain-boots.txt  
```

Similarly, the `Remove-Item` cmdlet removes both directories and files, whereas in Windows CLI we have separate commands `rmdir` and `del`.

```powershell title="Terminal"
PS C:\Users\captain\Documents> Remove-Item -Path ".\captain-cabin\captain-wardrobe\captain-boots.txt"
PS C:\Users\captain\Documents> Remove-Item -Path ".\captain-cabin\captain-wardrobe" 
```

We can copy or move files and directories alike, using respectively `Copy-Item` (equivalent to `copy`) and `Move-Item` (equivalent to `move`).

```powershell title="Terminal"
PS C:\Users\captain\Documents> Copy-Item -Path .\captain-cabin\captain-hat.txt -Destination .\captain-cabin\captain-hat2.txt
PS C:\Users\captain\Documents> Get-ChildItem -Path ".\captain-cabin\" 

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name 
----                 -------------         ------ ----
d-----          9/4/2024  12:50 PM                captain-wardrobe
-a----          9/4/2024  12:50 PM              0 captain-boots.txt
-a----          9/4/2024  12:14 PM            264 captain-hat.txt
-a----          9/4/2024  12:14 PM            264 captain-hat2.txt
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt 
```

Finally, to read and display the contents of a file, we can use the `Get-Content` cmdlet, which works similarly to the `type` command in Command Prompt (or `cat` in Unix-like systems).

:::info Answer the questions below

<details>

<summary> What cmdlet can you use instead of the traditional Windows command `type`? </summary>

```plaintext
Get-Content
```

</details>

<details>

<summary> What PowerShell command would you use to display the content of the "C:\Users" directory? [for the sake of this question, avoid the use of quotes (" or ') in your answer] </summary>

```plaintext
Get-ChildItem -Path C:\Users
```

</details>

<details>

<summary> How many items are displayed by the command described in the previous question? </summary>

```plaintext
4
```

</details>

:::

## Task 5 Piping, Filtering, and Sorting Data

`Piping` is a technique used in command-line environments that allows the output of one command to be used as the input for another. This creates a sequence of operations where the data flows from one command to the next. Represented by the `|` symbol, piping is widely used in the Windows CLI, as introduced earlier in this module, as well as in Unix-based shells.

In PowerShell, piping is even more powerful because it passes **objects** rather than just text. These objects carry not only the data but also the properties and methods that describe and interact with the data.

For example, if you want to get a list of files in a directory and then sort them by size, you could use the following command in PowerShell:

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Sort-Object Length

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:50 PM              0 captain-boots.txt
-a----          9/4/2024  12:14 PM            264 captain-hat2.txt
-a----          9/4/2024  12:14 PM            264 captain-hat.txt
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
d-----          9/4/2024  12:50 PM                captain-wardrobe
```

Here, `Get-ChildItem` retrieves the files (as objects), and the pipe (`|`) sends those file objects to `Sort-Object`, which then sorts them by their `Length` (size) property. This object-based approach allows for more detailed and flexible command sequences.

In the example above, we have leveraged the `Sort-Object` cmdlet to sort objects based on specified properties. Beyond sorting, PowerShell provides a set of cmdlets that, when combined with piping, allow for advanced data manipulation and analysis.

To filter objects based on specified conditions, returning only those that meet the criteria, we can use the `Where-Object` cmdlet. For instance, to list only `.txt`files in a directory, we can use:

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Where-Object -Property "Extension" -eq ".txt" 

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:50 PM              0 captain-boots.txt
-a----          9/4/2024  12:14 PM            264 captain-hat.txt
-a----          9/4/2024  12:14 PM            264 captain-hat2.txt
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
```

Here, `Where-Object` filters the files by their `Extension` property, ensuring that only files with extension equal (`-eq`) to `.txt` are listed.

The operator `-eq` (i.e. "**equal to**") is part of a set of **comparison operators** that are shared with other scripting languages (e.g. Bash, Python). To show the potentiality of the PowerShell's filtering, we have selected some of the most useful operators from that list:

- `-ne`: "**not equal**". This operator can be used to exclude objects from the results based on specified criteria.
- `-gt`: "**greater than**". This operator will filter only objects which exceed a specified value. It is important to note that this is a strict comparison, meaning that objects that are equal to the specified value will be excluded from the results.
- `-ge`: "**greater than or equal to**". This is the non-strict version of the previous operator. A combination of `-gt` and `-eq`.
- `-lt`: "**less than**". Like its counterpart, "greater than", this is a strict operator. It will include only objects which are strictly below a certain value.
- `-le`: "**less than or equal to**". Just like its counterpart `-ge`, this is the non-strict version of the previous operator. A combination of `-lt`and `-eq`.

Below, another example shows that objects can also be filtered by selecting properties that match (`-like`) a specified pattern:

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Where-Object -Property "Name" -like "ship*"  

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
```

The next filtering cmdlet, `Select-Object`, is used to select specific properties from objects or limit the number of objects returned. It’s useful for refining the output to show only the details one needs.

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Select-Object Name,Length 

Name              Length
----              ------
captain-wardrobe
captain-boots.txt 0
captain-hat.txt   264
captain-hat2.txt  264
ship-flag.txt     2116
```

The cmdlets pipeline can be extended by adding more commands, as the feature isn’t limited to just piping between two cmdlets. As an exercise, try and build a pipeline of cmdlets to sort and filter the output with the goal of displaying the largest file in the `C:\Users\captain\Documents\captain-cabin` directory.

<details>

<summary> Click here to look at a possible solution. Don’t cheat! </summary>

```powershell title="Terminal"
Get-ChildItem | Sort-Object Length -Descending | Select-Object -First 1

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
```

</details>

The last in this set of filtering cmdlets is `Select-String`. This cmdlet searches for text patterns within files, similar to `grep` in Unix-based systems or `findstr` in Windows Command Prompt. It’s commonly used for finding specific content within log files or documents.

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Select-String -Path ".\captain-hat.txt" -Pattern "hat" 

captain-hat.txt:8:Don't touch my hat!
```

The `Select-String` cmdlet fully supports the use of regular expressions (regex). This advanced feature allows for complex pattern matching within files, making it a powerful tool for searching and analysing text data.

:::info Answer the questions below

<details>

<summary> How would you retrieve the items in the current directory with size greater than 100? [for the sake of this question, avoid the use of quotes (" or ') in your answer] </summary>

```plaintext
Get-ChildItem | Where-Object -Property Length -gt 100
```

</details>

:::

## Task 6 System and Network Information

PowerShell was created to address a growing need for a powerful automation and management tool to help system administrators and IT professionals. As such, it offers a range of cmdlets that allow the retrieval of detailed information about system configuration and network settings.

The `Get-ComputerInfo` cmdlet retrieves comprehensive system information, including operating system information, hardware specifications, BIOS details, and more. It provides a snapshot of the entire system configuration in a single command. Its traditional counterpart `systeminfo` retrieves only a small set of the same details.

```powershell title="Terminal"
PS C:\Users\captain> Get-ComputerInfo

WindowsBuildLabEx                                       : 20348.859.amd64fre.fe_release_svc_prod2.220707-1832
WindowsCurrentVersion                                   : 6.3
WindowsEditionId                                        : ServerDatacenter
WindowsInstallationType                                 : Server Core
WindowsInstallDateFromRegistry                          : 4/23/2024 6:36:29 PM
WindowsProductId                                        : 00454-60000-00001-AA763
WindowsProductName                                      : Windows Server 2022 Datacenter
[...]
```

Essential for managing user accounts and understanding the machine’s security configuration, Get-LocalUser lists all the local user accounts on the system. The default output displays, for each user, username, account status, and description.

```powershell title="Terminal"
PS C:\Users\captain> Get-LocalUser

Name               Enabled Description 
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
captain            True    The beloved captain of this pirate ship.
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scenarios.
```

Similar to the traditional `ipconfig` command, the following two cmdlets can be used to retrieve detailed information about the system’s network configuration.

`Get-NetIPConfiguration` provides detailed information about the network interfaces on the system, including IP addresses, DNS servers, and gateway configurations.

```powershell title="Terminal"
PS C:\Users\captain> Get-NetIPConfiguration

InterfaceAlias       : Ethernet
InterfaceIndex       : 5
InterfaceDescription : Amazon Elastic Network Adapter
NetProfile.Name      : Network 3
IPv4Address          : 10.10.178.209
IPv6DefaultGateway   :
IPv4DefaultGateway   : 10.10.0.1
DNSServer            : 10.0.0.2
```

In case we need specific details about the IP addresses assigned to the network interfaces, the `Get-NetIPAddress` cmdlet will show details for all IP addresses configured on the system, including those that are not currently active.

```powershell title="Terminal"
PS C:\Users\captain> Get-NetIPAddress

IPAddress         : fe80::3fef:360c:304:64e%5
InterfaceIndex    : 5
InterfaceAlias    : Ethernet
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 64
PrefixOrigin      : WellKnown
SuffixOrigin      : Link
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : ::1
InterfaceIndex    : 1
InterfaceAlias    : Loopback Pseudo-Interface 1
AddressFamily     : IPv6
[...]

IPAddress         : 10.10.178.209
InterfaceIndex    : 5
InterfaceAlias    : Ethernet
AddressFamily     : IPv4
[...]

IPAddress         : 127.0.0.1
InterfaceIndex    : 1
InterfaceAlias    : Loopback Pseudo-Interface 1
AddressFamily     : IPv4
[...]
```

These cmdlets give IT professionals the ability to quickly access crucial system and network information directly from the command line, making it easier to monitor and manage both local and remote machines.

:::info Answer the questions below

<details>

<summary> Other than your current user and the default "Administrator" account, what other user is enabled on the target machine? </summary>

```plaintext
p1r4t3
```

</details>

<details>

<summary> This lad has hidden his account among the others with no regard for our beloved captain! What is the motto he has so bluntly put as his account's description? </summary>

```plaintext
A merry life and a short one.
```

</details>

<details>

<summary> Now a small challenge to put it all together. This shady lad that we just found hidden among the local users has his own home folder in the "C:\Users" directory.
Can you navigate the filesystem and find the hidden treasure inside this pirate's home? </summary>

```plaintext
THM{p34rlInAsh3ll}
```

</details>

:::

## Task 7 Real-Time System Analysis

To gather more advanced system information, especially concerning dynamic aspects like running processes, services, and active network connections, we can leverage a set of cmdlets that go beyond static machine details.

`Get-Process` provides a detailed view of all currently running processes, including CPU and memory usage, making it a powerful tool for monitoring and troubleshooting.

```powershell title="Terminal"
PS C:\Users\captain> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName 
-------  ------    -----      -----     ------     --  -- -----------
     67       5      872        500       0.06   2340   0 AggregatorHost
     55       5      712       2672       0.02   3024   0 AM_Delta_Patch_1.417.483.0
    309      13    18312       1256       0.52   1524   0 amazon-ssm-agent
     78       6     4440        944       0.02    516   0 cmd
     94       7     1224       1744       0.31    568   0 conhost
[...]
```

Similarly, `Get-Service` allows the retrieval of information about the status of services on the machine, such as which services are running, stopped, or paused. It is used extensively in troubleshooting by system administrators, but also by forensics analysts hunting for anomalous services installed on the system.

```powershell title="Terminal"
PS C:\Users\captain> Get-Service

Status   Name               DisplayName                           
------   ----               -----------
Stopped  Amazon EC2Launch   Amazon EC2Launch
Running  AmazonSSMAgent     Amazon SSM Agent
Stopped  AppIDSvc           Application Identity
Running  BFE                Base Filtering Engine
Running  CertPropSvc        Certificate Propagation
Stopped  ClipSVC            Client License Service (ClipSVC)
[...]
```

To monitor active network connections, `Get-NetTCPConnection` displays current TCP connections, giving insights into both local and remote endpoints. This cmdlet is particularly handy during an incident response or malware analysis task, as it can uncover hidden backdoors or established connections towards an attacker-controlled server.

```powershell title="Terminal"
PS C:\Users\captain> Get-NetTCPConnection

LocalAddress        LocalPort RemoteAddress       RemotePort State       AppliedSetting OwningProcess 
------------        --------- -------------       ---------- -----       -------------- -------------
[...]
::                  22        ::                  0          Listen                     1444          
10.10.178.209       49695     199.232.26.172      80         TimeWait                   0
0.0.0.0             49668     0.0.0.0             0          Listen                     424
0.0.0.0             49667     0.0.0.0             0          Listen                     652
0.0.0.0             49666     0.0.0.0             0          Listen                     388
0.0.0.0             49665     0.0.0.0             0          Listen                     560
0.0.0.0             49664     0.0.0.0             0          Listen                     672           
0.0.0.0             3389      0.0.0.0             0          Listen                     980
10.10.178.209       139       0.0.0.0             0          Listen                     4
0.0.0.0             135       0.0.0.0             0          Listen                     908
10.10.178.209       22        10.14.87.60         53523      Established Internet       1444
0.0.0.0             22        0.0.0.0             0          Listen                     1444
```

Additionally, we are going to mention `Get-FileHash` as a useful cmdlet for generating file hashes, which is particularly valuable in incident response, threat hunting, and malware analysis, as it helps verify file integrity and detect potential tampering.

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-FileHash -Path .\ship-flag.txt    

Algorithm       Hash                      Path 
---------       ----                      ----
SHA256          54D2EC3C12BF3D[...]       C:\Users\captain\Documents\captain-cabin\ship-flag.txt
```

These cmdlets collectively provide a comprehensive set of tools for real-time system monitoring and analysis, proving especially useful to incident responders and threat hunters.

:::info Answer the questions below

<details>

<summary> In the previous task, you found a marvellous treasure carefully hidden in the target machine. What is the hash of the file that contains it? </summary>

```plaintext
71FC5EC11C2497A32F8F08E61399687D90ABE6E204D2964DF589543A613F3E08
```

</details>

<details>

<summary> What property retrieved by default by `Get-NetTCPConnection` contains information about the process that has started the connection? </summary>

```plaintext
OwningProcess
```

</details>

<details>

<summary> It's time for another small challenge. Some vital service has been installed on this pirate ship to guarantee that the captain can always navigate safely. But something isn't working as expected, and the captain wonders why. Investigating, they find out the truth, at last: the service has been tampered with! The shady lad from before has modified the service `DisplayName` to reflect his very own motto, the same that he put in his user description. With this information and the PowerShell knowledge you have built so far, can you find the service name? </summary>

```plaintext
THM{p34rlInAsh3ll}
```

</details>

:::

## Task 8 Scripting

**Scripting** is the process of writing and executing a series of commands contained in a text file, known as a script, to automate tasks that one would generally perform manually in a shell, like PowerShell.

Simply speaking, scripting is like giving a computer a to-do list, where each line in the script is a task that the computer will carry out automatically. This saves time, reduces the chance of errors, and allows to perform tasks that are too complex or tedious to do manually. As you learn more about shells and scripting, you’ll discover that scripts can be powerful tools for managing systems, processing data, and much more.

Learning scripting with PowerShell goes beyond the scope of this room. Nonetheless, we must understand that its power makes it a crucial skill across all cyber security roles.

- For **blue team** professionals such as incident responders, malware analysts, and threat hunters, PowerShell scripts can automate many different tasks, including log analysis, detecting anomalies, and extracting indicators of compromise (IOCs). These scripts can also be used to reverse-engineer malicious code (malware) or automate the scanning of systems for signs of intrusion.
- For the **red team**, including penetration testers and ethical hackers, PowerShell scripts can automate tasks like system enumeration, executing remote commands, and crafting obfuscated scripts to bypass defences. Its deep integration with all types of systems makes it a powerful tool for simulating attacks and testing systems’ resilience against real-world threats.
- Staying in the context of cyber security, **system administrators** benefit from PowerShell scripting for automating integrity checks, managing system configurations, and securing networks, especially in remote or large-scale environments. PowerShell scripts can be designed to enforce security policies, monitor systems health, and respond automatically to security incidents, thus enhancing the overall security posture.

Whether used defensively or offensively, PowerShell scripting is an essential capability in the cyber security toolkit.

Before concluding this task about scripting, we can’t go without mentioning the `Invoke-Command` cmdlet.

`Invoke-Command` is essential for executing commands on remote systems, making it fundamental for system administrators, security engineers and penetration testers. `Invoke-Command` enables efficient remote management and—combining it with scripting—automation of tasks across multiple machines. It can also be used to execute payloads or commands on target systems during an engagement by penetration testers—or attackers alike.

Let us discover some example usage for this powerful cmdlet by consulting the `Get-Help` "examples" page:

```powershell title="Terminal"
PS C:\Users\captain> Get-Help Invoke-Command -examples

NAME
    Invoke-Command
    
SYNOPSIS
    Runs commands on local and remote computers.
    
    ------------- Example 1: Run a script on a server -------------
    
    Invoke-Command -FilePath c:\scripts\test.ps1 -ComputerName Server01
    
    The FilePath parameter specifies a script that is located on the local computer. The script runs on the remote computer and the results are returned to the local computer.

    --------- Example 2: Run a command on a remote server ---------

    Invoke-Command -ComputerName Server01 -Credential Domain01\User01 -ScriptBlock { Get-Culture }

    The ComputerName parameter specifies the name of the remote computer. The Credential parameter is used to run the command in the security context of Domain01\User01, a user who has permission to run commands. The ScriptBlock parameter specifies the command to be run on the remote computer.

    In response, PowerShell requests the password and an authentication method for the User01 account. It then runs the command on the Server01 computer and returns the result.
[...]
```

The first two examples provided by the `Get-Help` "examples" page and reported above are enough to grasp the simplicity and power of the `Invoke-Command` cmdlet.

The first example shows how the cmdlet can be very easily combined with any custom script to automate tasks on remote computers.

The second example demonstrates that we don't need to know how to script to benefit from the power of `Invoke-Command`. In fact, by appending the `-ScriptBlock { ... }` parameter to the cmdlet's syntax, we can execute any command (or sequence of commands) on the remote computer. The result would be the same as if we were typing the commands in a local PowerShell session on the remote computer itself.

:::info Answer the questions below

<details>

<summary> What is the syntax to execute the command `Get-Service` on a remote computer named "RoyalFortune"? Assume you don't need to provide credentials to establish the connection. [for the sake of this question, avoid the use of quotes (" or ') in your answer] </summary>

```plaintext
Invoke-Command -ComputerName RoyalFortune -ScriptBlock {Get-Service}
```

</details>

:::

## Task 9 Conclusion

Well done, mateys! You’ve successfully navigated the treacherous waters of PowerShell, uncovering hidden treasures and elusive services aboard TheBlackPearl.

With these tools in your belt, you’re well-equipped to explore even the most guarded corners of any Windows system.

Remember, a true pirate never stops seeking treasure—so keep honing your skills, and who knows what pearls you’ll discover in the next adventure? Until then, may your cmdlets be sharp and your scripts swift. Fair winds, and happy hunting!

To continue building up your command line skills, proceed to the [Linux Command Line](Linux%20Shells.md) room, up next in the module.

:::info Answer the questions below

<details>

<summary> I'm ready to go on to the next adventure! </summary>

```plaintext
No answer needed
```

</details>

:::
