---
sidebar_position: 1
---

# Windows PowerShell

## 任务 1 简介

你好！ 喂！ 如果你在这里，要么是听说了 PowerShell 的神奇之处想了解更多，要么是从命令行模块的第一个房间——[Windows 命令行](Windows%20Command%20Line.md)航行过来的。 无论哪种方式，你都将踏上一段旅程，探索这个强大 shell 的神奇之处，学习如何使用它来揭示任何 Windows 系统的秘密。 那么，停船！上船！ 无论如何，您即将踏上一段探索这个强大shell奇迹的旅程，学习如何使用它来揭示任何Windows系统的秘密。 那么，停船！上船！

### 学习目标

这是命令行模块中的第二个房间。 这是一个介绍 PowerShell 的房间，PowerShell 是第二个——仅从历史角度——为 Windows 操作系统构建的命令行实用程序。 这是一个关于PowerShell的介绍性房间，PowerShell是历史上第二个为Windows操作系统构建的命令行实用程序。

- 了解什么是 PowerShell 及其功能。
- 理解 PowerShell 语言的基本结构。
- 学习并运行一些基本的 PowerShell 命令。
- 理解 PowerShell 在网络安全行业中的许多应用。

### 房间先决条件

在接近这个房间之前，建议你已理解 Windows 和 AD 基础模块以及 Windows 命令行房间中的概念。

:::info 回答以下问题

<details>

<summary> 起锚，升帆——是时候起航了！ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 2 什么是 PowerShell

来自官方 Microsoft [页面](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.4)：“PowerShell 是一个跨平台的任务自动化解决方案，由命令行 shell、脚本语言和配置管理框架组成。”

PowerShell 是微软设计的一个强大工具，用于任务自动化和配置管理。 它结合了命令行界面和基于 .NET 框架构建的脚本语言。 与旧的基于文本的命令行工具不同，PowerShell 是面向对象的，这意味着它可以处理复杂的数据类型并更有效地与系统组件交互。 最初仅限 Windows，PowerShell 最近已扩展支持 macOS 和 Linux，使其成为跨不同操作系统的 IT 专业人士的通用选择。 它结合了命令行界面和基于.NET框架构建的脚本语言。 与较旧的基于文本的命令行工具不同，PowerShell是面向对象的，这意味着它可以处理复杂的数据类型并更有效地与系统组件交互。 最初仅限Windows使用，PowerShell最近已扩展到支持macOS和Linux，使其成为跨不同操作系统的IT专业人员的多功能选择。

### PowerShell 简史

PowerShell 的开发是为了克服 Windows 中现有命令行工具和脚本环境的局限性。 在 2000 年代初期，随着 Windows 在复杂的企业环境中日益使用，像 `cmd.exe` 和批处理文件这样的传统工具在自动化和管理这些系统方面表现不足。 微软需要一个能够处理更复杂管理任务并与 Windows 现代 API 交互的工具。 在21世纪初，随着Windows在复杂企业环境中的使用日益增多，像`cmd.exe`和批处理文件这样的传统工具在自动化和管理这些系统方面显得不足。 微软需要一个能够处理更复杂管理任务并与Windows现代API交互的工具。

微软工程师Jeffrey Snover意识到Windows和Unix处理系统操作的方式不同——Windows使用结构化数据和API，而Unix将所有内容视为文本文件。 这种差异使得将Unix工具移植到Windows不切实际。 Snover的解决方案是开发一种面向对象的方法，将脚本编写的简单性与.NET框架的强大功能相结合。 PowerShell于2006年发布，通过操作对象，使管理员能够更有效地自动化任务，提供与Windows系统的更深层次集成。

随着IT环境发展到包括各种操作系统，对多功能自动化工具的需求日益增长。 随着 IT 环境演变为包括各种操作系统，对通用自动化工具的需求增长。 2016 年，微软通过发布 PowerShell Core 做出回应，这是一个开源且跨平台的版本，可在 Windows、macOS 和 Linux 上运行。

### PowerShell 中的力量

要完全掌握 PowerShell 的力量，我们首先需要理解在此上下文中什么是**对象**。

在编程中，**对象**代表具有**属性**（特征）和**方法**（动作）的项。 在编程中，**对象**代表具有**属性**（特征）和**方法**（动作）的项。 例如，一个 `car` 对象可能具有像 `Color`、`Model` 和 `FuelLevel` 这样的属性，以及像 `Drive()`、`HonkHorn()` 和 `Refuel()` 这样的方法。

类似地，在 PowerShell 中，对象是封装数据和功能的基本单元，使得管理和操作信息更容易。 PowerShell 中的对象可以包含文件名、用户名或大小作为数据（**属性**），并携带函数（**方法**），例如复制文件或停止进程。 PowerShell中的对象可以包含文件名、用户名或大小作为数据（**属性**），并携带函数（**方法**），例如复制文件或停止进程。

传统命令 shell 的基本命令是基于文本的，这意味着它们以纯文本形式处理和输出数据。 相反，当在 PowerShell 中运行 **cmdlet**（发音为 command-let）时，它返回保留其属性和方法的对象。 这允许更强大和灵活的数据操作，因为这些对象不需要额外的文本解析。 相反，当在PowerShell中运行**cmdlet**（发音为command-let）时，它会返回保留其属性和方法的对象。 这允许更强大和灵活的数据操作，因为这些对象不需要额外的文本解析。

我们将在接下来的部分中探索更多关于 PowerShell 的 cmdlet 及其功能。

:::info 回答以下问题

<details>

<summary> 我们称用于开发 PowerShell 的高级方法为什么？ </summary>

```plaintext
object-oriented
```

</details>

:::

## 任务 3 PowerShell 基础

### 启动 PowerShell

PowerShell 可以通过几种方式启动，具体取决于你的需求和环境。 如果你从图形界面（GUI）在 Windows 系统上工作，这些是启动它的一些可能方式： 如果您从图形界面（GUI）在Windows系统上工作，以下是启动它的一些可能方式：

- **开始菜单**：在 Windows 开始菜单搜索栏中输入 `powershell`，然后从结果中点击 `Windows PowerShell` 或 `PowerShell`。
- **运行对话框**：按 `Win + R` 打开 `运行` 对话框，输入 `powershell`，然后按 `Enter`。
- **文件资源管理器**：导航到任何文件夹，然后在地址栏中输入 `powershell`，并按 `Enter`。 这将在该特定目录中打开 PowerShell。 这将在该特定目录中打开PowerShell。
- **任务管理器**：打开任务管理器，转到 `文件 > 运行新任务`，输入 `powershell`，然后按 `Enter`。

或者，可以通过在命令提示符（`cmd.exe`）中输入 `powershell` 并按 `Enter` 来启动 PowerShell。

在我们的情况下，我们只能访问目标 VM 的命令提示符，这是我们将使用的方法。

```powershell title="Terminal"
captain@THEBLACKPEARL C:\Users\captain>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\captain> 
```

PowerShell 启动后，我们在当前工作目录中看到一个 `PS`（代表 `PowerShell`）提示符。

### 基本语法：动词-名词

如前所述，PowerShell 命令被称为 `cmdlets`（发音为 `command-lets`）。 它们比传统的 Windows 命令强大得多，并允许更高级的数据操作。 它们比传统的Windows命令强大得多，并允许更高级的数据操作。

Cmdlets 遵循一致的 `动词-名词` 命名约定。 这种结构使得理解每个 cmdlet 的作用变得容易。 `动词` 描述动作，`名词` 指定执行动作的对象。 例如： 这种结构使得理解每个cmdlet的功能变得容易。 `Verb`描述动作，而`Noun`指定执行动作的对象。 例如：

- `Get-Content`：检索（获取）文件的内容并在控制台中显示。
- `Set-Location`：更改（设置）当前工作目录。

### 基本 Cmdlets

要列出当前 PowerShell 会话中所有可执行的 cmdlet、函数、别名和脚本，我们可以使用 `Get-Command`。 它是发现可以使用哪些命令的基本工具。 它是发现可以使用哪些命令的基本工具。

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

对于 cmdlet 检索的每个 `CommandInfo` 对象，一些基本信息（属性）显示在控制台上。 可以根据显示的属性值过滤命令列表。 例如，如果我们只想显示类型为“function”的可用命令，我们可以使用 `-CommandType "Function"`，如下所示： 可以根据显示的属性值过滤命令列表。 例如，如果我们只想显示类型为“function”的可用命令，我们可以使用`-CommandType "Function"`，如下所示：

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

我们将在后续任务中学习更高效地筛选cmdlet输出的方法。

我们工具箱中另一个必不可少的cmdlet是`Get-Help`：它提供有关cmdlet的详细信息，包括用法、参数和示例。 这是学习如何使用PowerShell命令的首选cmdlet。 它是学习如何使用PowerShell命令的首选cmdlet。

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

如上所示，`Get-Help`告知我们可以通过在基本语法后附加一些选项来获取有关cmdlet的其他有用信息。 例如，通过在上方显示的命令后附加`-examples`，我们将看到所选cmdlet的常用用法列表。 例如，通过将`-examples`附加到上面显示的命令，我们将看到所选cmdlet可以使用的常见方式列表。

为了让IT专业人员更容易过渡，PowerShell包含了许多传统Windows命令的别名——即cmdlet的快捷方式或替代名称。 对于已经熟悉其他命令行工具的用户来说，`Get-Alias`列出了所有可用的别名，这是必不可少的。 例如，`dir`是`Get-ChildItem`的别名，`cd`是`Set-Location`的别名。 对于已经熟悉其他命令行工具的用户来说，`Get-Alias`列出了所有可用的别名。 例如，`dir`是`Get-ChildItem`的别名，`cd`是`Set-Location`的别名。

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

### 在哪里查找和下载Cmdlet

PowerShell的另一个强大功能是通过从在线存储库下载额外的cmdlet来扩展其功能。

**注意**：请注意，本节列出的cmdlet需要有效的互联网连接来查询在线存储库。 附加的机器无法访问互联网，因此这些命令在此环境中无法工作。 附加的机器无法访问互联网，因此这些命令在此环境中无法工作。

要在PowerShell Gallery等在线存储库中搜索模块（cmdlet集合），我们可以使用`Find-Module`。 有时，如果我们不知道模块的确切名称，搜索具有相似名称的模块会很有用。 我们可以通过过滤`Name`属性并在模块的部分名称后附加通配符（`*`）来实现这一点，使用以下标准PowerShell语法：`Cmdlet -Property "pattern*"`。 有时，如果我们不知道模块的确切名称，搜索具有相似名称的模块可能很有用。 我们可以通过过滤`Name`属性并在模块的部分名称后附加通配符（`*`）来实现这一点，使用以下标准PowerShell语法：`Cmdlet -Property "pattern*"`。

```powershell title="Terminal"
PS C:\Users\captain> Find-Module -Name "PowerShell*"   

Version    Name                                Repository           Description 
-------    ----                                ----------           ----------- 
0.4.7      powershell-yaml                     PSGallery            Powershell module for serializing and deserializing YAML

2.2.5      PowerShellGet                       PSGallery            PowerShell module with commands for discovering, installing, updating and publishing the PowerShell artifacts like Modules, DSC Resources, Role Capabilities and Scripts.                                                   
1.0.80.0   PowerShell.Module.InvokeWinGet      PSGallery            Module to Invoke WinGet and parse the output in PSOjects

0.17.0     PowerShellForGitHub                 PSGallery            PowerShell wrapper for GitHub API  
```

一旦识别出模块，就可以使用`Install-Module`从存储库下载并安装它们，使模块中包含的新cmdlet可供使用。

```powershell title="Terminal"
PS C:\Users\captain> Install-Module -Name "PowerShellGet"

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): 
```

有了这些基本工具，我们现在可以开始探索PowerShell的功能了。

:::info 回答以下问题

<details>

<summary> 如何检索以动词`Remove`**开头**的命令列表？ [为了这个问题，请避免在答案中使用引号（"或'）] </summary>

```plaintext
Get-Command -Name Remove*
```

</details>

<details>

<summary> 哪个cmdlet的传统对应别名是`echo`？ </summary>

```plaintext
Write-Output
```

</details>

<details>

<summary> 获取cmdlet `New-LocalUser`的一些示例用法的命令是什么？ </summary>

```plaintext
Get-Help New-LocalUser -examples
```

</details>

:::

## 任务4 导航文件系统和处理文件

PowerShell提供了一系列用于导航文件系统和管理文件的cmdlet，其中许多在传统Windows CLI中有对应命令。

类似于命令提示符中的`dir`命令（或类Unix系统中的`ls`），`Get-ChildItem`列出使用`-Path`参数指定的位置中的文件和目录。 它可以用于探索目录并查看其内容。 如果未指定`Path`，该cmdlet将显示当前工作目录的内容。 它可以用于探索目录并查看其内容。 如果未指定`Path`，cmdlet将显示当前工作目录的内容。

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

要导航到不同的目录，我们可以使用`Set-Location` cmdlet。 它更改当前目录，将我们带到指定路径，类似于命令提示符中的`cd`命令。 它更改当前目录，将我们带到指定路径，类似于命令提示符中的`cd`命令。

```powershell title="Terminal"
PS C:\Users\captain> Set-Location -Path ".\Documents"
PS C:\Users\captain\Documents> 
```

虽然传统的Windows CLI使用单独的命令来创建和管理不同的项目（如目录和文件），但PowerShell通过提供一组统一的cmdlet来处理文件和目录的创建和管理，简化了这一过程。

要在PowerShell中创建项目，我们可以使用`New-Item`。 我们需要指定项目的路径及其类型（无论是文件还是目录）。 我们需要指定项的路径及其类型（无论是文件还是目录）。

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

类似地，`Remove-Item` cmdlet可删除目录和文件，而在Windows CLI中我们有单独的命令`rmdir`和`del`。

```powershell title="Terminal"
PS C:\Users\captain\Documents> Remove-Item -Path ".\captain-cabin\captain-wardrobe\captain-boots.txt"
PS C:\Users\captain\Documents> Remove-Item -Path ".\captain-cabin\captain-wardrobe" 
```

我们可以分别使用`Copy-Item`（相当于`copy`）和`Move-Item`（相当于`move`）来复制或移动文件和目录。

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

最后，要读取并显示文件内容，我们可以使用 `Get-Content` cmdlet，其功能类似于命令提示符中的 `type` 命令（或类 Unix 系统中的 `cat` 命令）。

:::info 回答以下问题

<details>

<summary> 你可以使用哪个 cmdlet 来替代传统的 Windows 命令 `type`？ </summary>

```plaintext
Get-Content
```

</details>

<details>

<summary> 你会使用哪个 PowerShell 命令来显示 "C:\Users" 目录的内容？ [为了本题目的，请在答案中避免使用引号（" 或 '）] </summary>

```plaintext
Get-ChildItem -Path C:\Users
```

</details>

<details>

<summary> 上一个问题中描述的命令显示了几个项目？ </summary>

```plaintext
4
```

</details>

:::

## 任务 5 管道、过滤和排序数据

`Piping`是命令行环境中使用的一种技术，允许将一个命令的输出用作另一个命令的输入。 这创建了一个操作序列，其中数据从一个命令流向下一个命令。 由`|`符号表示，管道在Windows CLI中广泛使用，如本模块前面介绍的那样，以及在基于Unix的shell中。

在 PowerShell 中，管道更加强大，因为它传递的是 **对象** 而不仅仅是文本。 这些对象不仅携带数据，还携带描述数据并与数据交互的属性和方法。 这些对象不仅携带数据，还携带描述数据并与数据交互的属性和方法。

例如，如果你想获取目录中的文件列表，然后按大小排序，可以在 PowerShell 中使用以下命令：

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

这里，`Get-ChildItem` 检索文件（作为对象），管道（`|`）将这些文件对象发送到 `Sort-Object`，然后按它们的 `Length`（大小）属性进行排序。 这种基于对象的方法允许更详细和灵活的命令序列。 这种基于对象的方法允许更详细和灵活的命令序列。

在上面的示例中，我们利用了 `Sort-Object` cmdlet 来根据指定属性对对象进行排序。 除了排序，PowerShell 还提供了一组 cmdlet，当与管道结合使用时，允许进行高级数据操作和分析。 除了排序，PowerShell提供了一组cmdlet，当与管道结合使用时，允许高级数据操作和分析。

要根据指定条件过滤对象，仅返回符合标准的对象，我们可以使用 `Where-Object` cmdlet。 例如，要仅列出目录中的 `.txt` 文件，我们可以使用： 例如，要仅列出目录中的`.txt`文件，我们可以使用：

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

这里，`Where-Object` 通过文件的 `Extension` 属性进行过滤，确保仅列出扩展名等于（`-eq`）`.txt` 的文件。

运算符 `-eq`（即 "**等于**"）是一组 **比较运算符** 的一部分，这些运算符与其他脚本语言（例如 Bash、Python）共享。 为了展示 PowerShell 过滤的潜力，我们从该列表中挑选了一些最有用的运算符： 为了展示PowerShell过滤的潜力，我们从该列表中挑选了一些最有用的运算符：

- `-ne`："**不等于**"。 此运算符可用于根据指定条件从结果中排除对象。
- `-gt`："**大于**"。 此运算符将仅过滤超过指定值的对象。 需要注意的是，这是一个严格比较，意味着等于指定值的对象将被排除在结果之外。
- `-ge`："**大于或等于**"。 这是前一个运算符的非严格版本。 `-ge`："**大于或等于**"。 这是前一个运算符的非严格版本。 `-gt` 和 `-eq` 的组合。
- `-lt`："**小于**"。 与其对应项"大于"一样，这是一个严格运算符。 它将仅包括严格低于某个值的对象。
- `-le`："**小于或等于**"。 就像其对应项`-ge`一样，这是前一个运算符的非严格版本。 `-lt`和`-eq`的组合。

下面，另一个示例显示对象也可以通过选择匹配（`-like`）指定模式的属性进行过滤：

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-ChildItem | Where-Object -Property "Name" -like "ship*"  

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
```

下一个过滤 cmdlet `Select-Object` 用于从对象中选择特定属性或限制返回的对象数量。 它对于将输出精炼为仅显示所需细节非常有用。 它对于优化输出以仅显示所需细节非常有用。

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

cmdlet管道可以通过添加更多命令来扩展，因为该功能不仅限于在两个cmdlet之间进行管道传输。 cmdlet 管道可以通过添加更多命令来扩展，因为该功能不仅限于在两个 cmdlet 之间进行管道传输。 作为练习，尝试构建一个 cmdlet 管道来排序和过滤输出，目标是显示 `C:\Users\captain\Documents\captain-cabin` 目录中最大的文件。

<details>

<summary> 点击此处查看可能的解决方案。 不要作弊！ </summary>

```powershell title="Terminal"
Get-ChildItem | Sort-Object Length -Descending | Select-Object -First 1

    Directory: C:\Users\captain\Documents\captain-cabin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/4/2024  12:37 PM           2116 ship-flag.txt
```

</details>

这组过滤cmdlet中的最后一个是`Select-String`。 这组过滤 cmdlet 中的最后一个是 `Select-String`。 此 cmdlet 在文件中搜索文本模式，类似于基于 Unix 系统中的 `grep` 或 Windows 命令提示符中的 `findstr`。 它通常用于在日志文件或文档中查找特定内容。 它通常用于在日志文件或文档中查找特定内容。

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Select-String -Path ".\captain-hat.txt" -Pattern "hat" 

captain-hat.txt:8:Don't touch my hat!
```

`Select-String` cmdlet 完全支持使用正则表达式（regex）。 此高级功能允许在文件内进行复杂的模式匹配，使其成为搜索和分析文本数据的强大工具。 此高级功能允许在文件内进行复杂模式匹配，使其成为搜索和分析文本数据的强大工具。

:::info 回答以下问题

<details>

<summary> 你将如何检索当前目录中大小大于 100 的项目？ [为了本题目的，请在答案中避免使用引号（" 或 '）] </summary>

```plaintext
Get-ChildItem | Where-Object -Property Length -gt 100
```

</details>

:::

## 任务6 系统和网络信息

PowerShell的创建是为了满足日益增长的对强大自动化和管理工具的需求，以帮助系统管理员和IT专业人员。 因此，它提供了一系列cmdlet，允许检索有关系统配置和网络设置的详细信息。 因此，它提供了一系列cmdlet，允许检索有关系统配置和网络设置的详细信息。

`Get-ComputerInfo` cmdlet检索全面的系统信息，包括操作系统信息、硬件规格、BIOS详细信息等。 它通过单个命令提供整个系统配置的快照。 其传统对应物`systeminfo`仅检索相同详细信息的一小部分。 它在单个命令中提供整个系统配置的快照。 其传统对应项`systeminfo`仅检索相同细节的一小部分。

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

对于管理用户帐户和理解机器的安全配置至关重要，Get-LocalUser列出系统上的所有本地用户帐户。 默认输出显示每个用户的用户名、帐户状态和描述。 默认输出显示每个用户的用户名、帐户状态和描述。

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

类似于传统的`ipconfig`命令，以下两个cmdlet可用于检索有关系统网络配置的详细信息。

`Get-NetIPConfiguration`提供有关系统上网络接口的详细信息，包括IP地址、DNS服务器和网关配置。

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

如果我们需要有关分配给网络接口的IP地址的具体详细信息，`Get-NetIPAddress` cmdlet将显示系统上配置的所有IP地址的详细信息，包括当前未激活的地址。

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

这些cmdlet使IT专业人员能够直接从命令行快速访问关键系统和网络信息，从而更轻松地监控和管理本地和远程机器。

:::info 回答以下问题

<details>

<summary>除了您当前用户和默认的"Administrator"帐户外，目标机器上还有哪个其他用户已启用？ </summary>

```plaintext
p1r4t3
```

</details>

<details>

<summary>这个家伙毫不顾及我们敬爱的船长，将他的帐户隐藏在其他帐户中！ 他如此直白地将其帐户描述设置为什么座右铭？ </summary>

```plaintext
A merry life and a short one.
```

</details>

<details>

<summary> 现在是一个将所有内容整合起来的小挑战。 我们刚刚在本地用户中发现的这个可疑家伙在 "C:\Users" 目录中有他自己的主文件夹。你能导航文件系统并找到这个海盗家中隐藏的宝藏吗？ </summary>

```plaintext
THM{p34rlInAsh3ll}
```

</details>

:::

## 任务7 实时系统分析

为了收集更高级的系统信息，特别是关于动态方面的信息，如运行进程、服务和活动网络连接，我们可以利用一组超越静态机器详细信息的cmdlet。

`Get-Process`提供所有当前运行进程的详细视图，包括CPU和内存使用情况，使其成为监控和故障排除的强大工具。

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

类似地，`Get-Service`允许检索有关机器上服务状态的信息，例如哪些服务正在运行、已停止或已暂停。 它被系统管理员广泛用于故障排除，也被法证分析师用于查找系统上安装的异常服务。 它被系统管理员广泛用于故障排除，也被法证分析师用于搜寻系统中安装的异常服务。

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

要监控活跃的网络连接，`Get-NetTCPConnection` 显示当前的 TCP 连接，提供对本地和远程端点的洞察。 为了监控活动网络连接，`Get-NetTCPConnection`显示当前TCP连接，提供对本地和远程端点的洞察。 这个cmdlet在事件响应或恶意软件分析任务中特别方便，因为它可以发现隐藏的后门或指向攻击者控制服务器的已建立连接。

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

此外，我们将提到`Get-FileHash`作为一个有用的cmdlet，用于生成文件哈希，这在事件响应、威胁狩猎和恶意软件分析中特别有价值，因为它有助于验证文件完整性并检测潜在的篡改。

```powershell title="Terminal"
PS C:\Users\captain\Documents\captain-cabin> Get-FileHash -Path .\ship-flag.txt    

Algorithm       Hash                      Path 
---------       ----                      ----
SHA256          54D2EC3C12BF3D[...]       C:\Users\captain\Documents\captain-cabin\ship-flag.txt
```

这些cmdlet共同提供了一套全面的工具，用于实时系统监控和分析，对事件响应者和威胁猎人特别有用。

:::info 回答以下问题

<details>

<summary> 在之前的任务中，你在目标机器中找到了一个精心隐藏的奇妙宝藏。 包含它的文件的哈希值是什么？ </summary>

```plaintext
71FC5EC11C2497A32F8F08E61399687D90ABE6E204D2964DF589543A613F3E08
```

</details>

<details>

<summary>默认情况下，`Get-NetTCPConnection`检索的哪个属性包含有关启动连接的进程的信息？ </summary>

```plaintext
OwningProcess
```

</details>

<details>

<summary> 是时候进行另一个小挑战了。 这艘海盗船上安装了一些重要服务，以确保船长总能安全航行。 但有些东西没有按预期工作，船长想知道原因。 经过调查，他们终于发现了真相：该服务已被篡改！ 之前那个可疑的家伙修改了服务的 `DisplayName` 以反映他自己的口号，与他放在用户描述中的相同。 有了这些信息以及你到目前为止积累的 PowerShell 知识，你能找到服务名称吗？ </summary>

```plaintext
THM{p34rlInAsh3ll}
```

</details>

:::

## 任务8 脚本编写

**脚本编写**是编写和执行文本文件（称为脚本）中包含的一系列命令的过程，用于自动化通常在PowerShell等shell中手动执行的任务。

简单来说，脚本编写就像给计算机一个待办事项列表，脚本中的每一行都是计算机将自动执行的任务。 这可以节省时间，减少出错的可能性，并允许执行过于复杂或繁琐而无法手动完成的任务。 随着您对shell和脚本编写的深入了解，您会发现脚本是管理系统、处理数据等的强大工具。 这节省了时间，减少了出错的机会，并允许执行过于复杂或繁琐而无法手动完成的任务。 随着你对 shell 和脚本编写的了解加深，你会发现脚本是管理系统、处理数据等的强大工具。

学习PowerShell脚本编写超出了本房间的范围。 尽管如此，我们必须理解其强大功能使其成为所有网络安全角色中的关键技能。 然而，我们必须理解，它的强大使其成为所有网络安全角色中的关键技能。

- 对于**蓝队**专业人员，如事件响应者、恶意软件分析师和威胁猎人，PowerShell脚本可以自动化许多不同的任务，包括日志分析、检测异常和提取入侵指标（IOC）。 这些脚本还可用于逆向工程恶意代码（恶意软件）或自动化扫描系统以寻找入侵迹象。 这些脚本也可用于逆向工程恶意代码（恶意软件）或自动扫描系统以寻找入侵迹象。
- 对于**红队**，包括渗透测试人员和道德黑客，PowerShell脚本可以自动化系统枚举、执行远程命令和制作混淆脚本以绕过防御等任务。 其与所有类型系统的深度集成使其成为模拟攻击和测试系统对现实世界威胁的抵御能力的强大工具。 它与所有类型系统的深度集成使其成为模拟攻击和测试系统抵御现实世界威胁能力的强大工具。
- 在网络安全背景下，**系统管理员**受益于PowerShell脚本编写，用于自动化完整性检查、管理系统配置和保护网络，尤其是在远程或大规模环境中。 PowerShell脚本可以设计为强制执行安全策略、监控系统健康状况并自动响应安全事件，从而增强整体安全态势。 PowerShell 脚本可以设计用于强制执行安全策略、监控系统健康状况并自动响应安全事件，从而增强整体安全态势。

无论是用于防御还是进攻，PowerShell脚本编写都是网络安全工具包中的基本能力。

在结束这个关于脚本编写的任务之前，我们不能不提到`Invoke-Command` cmdlet。

`Invoke-Command` 对于在远程系统上执行命令至关重要，使其成为系统管理员、安全工程师和渗透测试人员的基础工具。 `Invoke-Command` 实现了高效的远程管理，并结合脚本编写，实现了跨多台机器的任务自动化。 它也可用于在渗透测试人员（或攻击者）参与期间在目标系统上执行有效载荷或命令。

让我们通过查阅`Get-Help`的"示例"页面来了解这个强大cmdlet的一些示例用法：

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

`Get-Help` "示例"页面提供并报告的前两个示例足以理解`Invoke-Command` cmdlet的简单性和强大功能。

第一个示例展示了如何非常轻松地将cmdlet与任何自定义脚本结合，以自动化远程计算机上的任务。

第二个示例证明我们不需要知道如何编写脚本即可受益于`Invoke-Command`的强大功能。 实际上，通过附加 `-ScriptBlock { ... }`参数附加到cmdlet的语法中，我们可以在远程计算机上执行任何命令（或命令序列）。 结果将与我们直接在远程计算机上的本地PowerShell会话中键入命令相同。 结果将与我们直接在远程计算机本地的 PowerShell 会话中键入命令相同。

:::info 回答以下问题

<details>

<summary> 在名为"RoyalFortune"的远程计算机上执行`Get-Service`命令的语法是什么？ 假设您不需要提供凭据来建立连接。 [为了这个问题，请在答案中避免使用引号（"或'）] </summary>

```plaintext
Invoke-Command -ComputerName RoyalFortune -ScriptBlock {Get-Service}
```

</details>

:::

## 任务9 结论

干得好，伙计们！ 干得好，伙计们！ 您已成功驾驭了PowerShell的险恶水域，在"黑珍珠号"上发现了隐藏的宝藏和难以捉摸的服务。

有了这些工具，您已装备齐全，可以探索任何Windows系统中最受保护的角落。

记住，真正的海盗永远不会停止寻找宝藏——所以继续磨练您的技能，谁知道在下次冒险中您会发现什么珍珠？ 在那之前，愿您的cmdlet锋利，脚本迅捷。 顺风而行，狩猎愉快！ 在那之前，愿你的 cmdlet 锋利，脚本迅捷。 顺风航行，狩猎愉快！

要继续构建您的命令行技能，请继续学习模块中的下一个房间：[Linux命令行](Linux%20Shells.md)。

:::info 回答以下问题

<details>

<summary> 我已准备好进入下一次冒险！ </summary>

```plaintext
No answer needed
```

</details>

:::
