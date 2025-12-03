---
sidebar_position: 1
---

# 内存获取

## 任务 1 介绍

在分析内存之前，您必须先获取它。 这涉及将易失性内存的内容复制到非易失性存储中（《内存取证的艺术》）。 内存分析的有效性取决于内存获取过程的质量——准确捕获内存与解释它同样重要。 在本房间中，我们将讨论在内存获取之前、期间和之后需要考虑的所有变量。 这些变量包括工具、时机、格式、环境等。 然后，您将继续在Windows、Linux和Hypervisor上有效创建符合取证要求的内存映像。

### 学习目标

- 在Windows上创建符合取证要求的内存映像
- 在Linux上创建符合取证要求的内存映像
- 在Hypervisor上创建符合取证要求的内存映像
- 在云环境中创建符合取证要求的内存映像
- 在获取过程中理解并应用最佳实践

### 房间先决条件

- [内存分析简介](https://tryhackme.com/room/memoryanalysisintroduction)
- [Windows基础](https://tryhackme.com/module/windows-fundamentals)
- [Linux基础](https://tryhackme.com/module/linux-fundamentals)

:::info 回答以下问题

<details>

<summary> 您准备好捕获内存了吗？ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务2 技术、工具和最佳实践

内存获取过程并非从您捕获RAM映像并将其传输到非易失性存储时开始。 它在此之前的很早就开始了，作为您在事件响应计划中概述的一系列明确定义的选择。 此概述应详细说明以下决策：

- 使用哪种获取技术
- 使用哪些工具
- 时机
- 关注内存的哪个部分
- 确保完整性

本任务将涵盖这些基本考虑因素中的每一个。

### 选择正确的内存部分

在系统上获取内存之前，您必须确定内存的哪个部分具有取证价值。 这是根据具体情况决定的，并将受到您观察到的IOA和IOC的影响。 考虑以下示例：

- **异常资源使用**：您注意到一个常见进程使用了异常数量的CPU和内存。 您决定获取进程映像（也称为进程转储）。 在这种情况下，完整内存转储将花费太长时间并包含太多取证噪声，妨碍分析。

- **恶意软件感染**：您发现了一个受恶意软件感染的主机，并在防火墙日志中发现了该主机具有活跃C2连接的证据。 您决定进行完整内存捕获以协助调查。

- **系统关闭**：您在员工的系统上检测到欺诈迹象。 为了避免惊动该员工，您决定在午餐休息期间进行内存捕获。 相关系统已关闭电源。 幸运的是，由于配置的策略，系统进入了休眠状态，您可以获取`hiberfil.sys`文件进行分析。

在下表中，您可以找到可以获取的内存转储类型、其内容和用例的概述。 请注意，`pagefile`、`Hibernation File`和`VM Memory file`不是直接的内存转储。 它们是执行某种类型操作后存在于磁盘上的文件。 页面文件填充了已暂停或最近终止的进程的内存；休眠文件是主机系统进入休眠模式时创建的；VM内存文件是在保存或快照VM状态时创建的。

| 类型                    | 捕获内容                                    | 用例                                   |
| :-------------------- | :-------------------------------------- | :----------------------------------- |
| **完整内存转储**            | 整个物理内存（RAM）                             | 完整取证分析、恶意软件行为、对CTI也很有价值              |
| **进程转储/核心转储**         | 单个进程的内存（堆、栈、代码、模块）                      | 检测恶意软件注入、行为分析                        |
| **内存区域转储**            | 进程的特定区域（例如，栈、堆、注入代码）                    | 专注于提取恶意软件或shellcode                  |
| **页面文件/交换文件**         | 交换出的虚拟内存（`pagefile.sys` - `\swapfile`） | 收集最近终止/暂停进程的内存                       |
| **休眠文件转储（仅限Windows）** | 休眠期间保存的RAM快照（`hiberfil.sys`）            | 来自休眠系统的完整内存捕获（例如，笔记本电脑）。 在实时内存不可用时使用 |
| **VM内存转储**            | 虚拟机的易失性内存                               | 安全的恶意软件测试、可重放的事件分析                   |

在接下来的任务中，您将在Windows和Linux上执行多种这些类型的捕获。

### 选择合适的文件格式

在内存映像方面没有标准格式。 因此，您必须选择与您将用于分析的工具兼容的格式。 内存转储格式将在很大程度上取决于您针对的平台和您使用的工具。 下面，我们列出了最常见的格式。

- `.raw`和`.mem`：此格式是在大多数操作系统（如macOS、Windows和Linux）上支持的原始物理内存转储。 它也是确保与大多数分析工具兼容的首选格式
- `.dmp`：这是Windows内置的内存转储格式。 Windows包含多种类型的`.dmp`文件，在大多数情况下需要先进行配置。 您将在“Windows内存获取”任务中探索这一点
- VM格式（`.vmem`、`.vmsn`、`.vmss`、`.bin`、`.sav`）：这些文件表示虚拟机在Hypervisor（如VMware、Hyper-V或VirtualBox）中拍摄快照或暂停后的内存状态。 请注意，您需要转换`.sav`文件才能在分析中使用
- `.core`：这是在Linux中使用`gcore`工具以ELF格式化的进程级内存转储。 当进程崩溃时也会创建此类文件
- Expert Witness Format：此格式是使用Encase工具生成的，该工具是高级取证分析的行业标准
- `.lime`：此内存捕获文件是使用LiME（Linux内存提取器）工具创建的结构化完整内存转储

### 选择获取技术

有多种方法可以在系统上获取内存。 根据您的用例，您将选择其中一种。 让我们看看可以使用哪些方法。

- **本地**：您取一个外部存储设备，将其插入目标机器，然后运行工具以获取内存。 此方法需要对目标系统进行物理访问
- **远程**：您运行工具以获取内存，然后通过网络传输内存捕获。 这种方法非常适合需要针对难以亲自访问的机器的情况，例如没有连接任何键盘或显示器的物理服务器，或者位于您主要工作地点以外的系统
- **硬件**：您已安装专用PCIe卡，允许您在不访问操作系统的情况下获取内存
- **RAM冻结**：RAM是易失性的，断电后内容在几秒钟内就会消失。 一种技术涉及冻结RAM，这可以使RAM内容保留更长时间。 根据冻结方法的不同，这将为您提供足够的时间将RAM模块移动到另一个系统，该系统具有专用操作系统，可以对RAM模块进行内存转储

#### 重要注意事项

- 您需要管理员权限才能获取完整的内存转储
- 远程传输获取的内存时，接收系统也被入侵的风险。 这可能是由于恶意软件的性质或攻击者利用机会进行横向移动
- 使用本地存储时，存储设备也有可能被入侵。 使用一次性系统进行初步分析
- 硬件卡是一种成本较高的内存获取选项。 确保成本与系统的重要性相匹配

### 工具

为正确的工作选择正确的工具是决定内存捕获质量的关键因素。 没有工具适合所有用例，因此仔细考虑可用选项非常重要。 您应考虑以下因素：

- 完整性
- 兼容性
- 速度和可扩展性
- 合规性
- 成本
- 引入的取证噪声

以下是一些最常用的工具。

| 商业工具                                                                     | 免费工具               |
| :----------------------------------------------------------------------- | :----------------- |
| EnCase Forensic                                                          | FTK Imager         |
| CaptureGUARD (PCIe & ExpressCard) | Magnet RAM Capture |
| F-Response                                                               | DumpIt             |
| Cellebrite UFED                                                          | WinPmem/LinuxPmem  |
| PCILeech                                                                 | LiMe               |

### 内存捕获时机

进行内存捕获时，时机至关重要。 RAM的内容不断变化，这意味着内存捕获仅包含该时刻的内容。 适当的时机可以让您最大程度地成功捕获有价值的取证证据。 以下场景说明了时机的重要性：

- **横向移动**：您确定了一个可能用作横向移动入口点的主机。 您决定对其进行监控，当您注意到可疑活动时，立即进行内存捕获，从而获得可操作的取证证据，如正在运行的远程会话、受损的用户凭据等等。
- **无文件恶意软件**：您在系统上检测到一个显示异常行为的常见进程。 您决定进行内存捕获以进行分析。 由于您的快速决策，您发现了恶意的PowerShell脚本、活跃的C2 IP地址以及攻击者的下一阶段有效载荷。
- **证据销毁**：您注意到用户在其系统上的异常行为。 该用户已将敏感文档复制到其本地系统。 您向该用户发送消息询问此行为。 该用户突然显示为离线，因此您亲自检查其系统。 当您到达用户办公桌时，您注意到用户的系统正在重新启动。 用户表示其系统出现了一些奇怪的情况，因此他重新启动了系统。 不幸的是，您失去了收集潜在数据外泄证据的机会。

#### 其他注意事项

- 攻击者通常在特定时间段活动，并在被发现时尝试删除证据，并完全在内存中运行其恶意软件
- 尽量避免在内存变化较快的时间段进行捕获，例如启动期间、病毒扫描期间、备份期间等

结论

您已经发现了获取内存时需要考虑的基本注意事项。 这些注意事项实际上构成了内存获取流程。 在以下任务中，当获取内存时，您将需要反复基于这些注意事项做出决策。
您需要回答以下问题：

- 我需要获取内存的**哪一部分**？
- 我将使用**哪种工具**和/或技术来获取内存？
- 我**何时**捕获内存？
- 我将如何确保**完整性**？

![内存获取流程](img/image_20251123-092328.png)

:::info 回答以下问题

<details>

<summary> 包含休眠Windows系统内存的文件名是什么？ 答案格式为：文件名.扩展名 </summary>

```plaintext
hiberfil.sys
```

</details>

<details>

<summary> 您可以使用哪种工具在Linux主机上获取进程内存转储？ </summary>

```plaintext
gcore
```

</details>

:::

## 任务3 Windows内存获取

### 简介

在Windows主机上获取内存很简单。 您可以应用上一个任务中列出的步骤：内容、时机、工具和完整性。 在此任务中，您将专注于在正常工作时间获取以下内存转储：

- 使用`FTK imager`工具进行完整内存捕获
- 使用`SysinternalsSuite`中的`procdump.exe`工具进行进程内存转储
- 配置Windows在系统崩溃时生成小型内存转储

内存转储的格式应与您稍后将使用的内存分析工具兼容。 对于此任务及后续任务，您需要确保与`volatility`兼容。 选择`volatility`很简单。 它是一个具有许多强大功能的免费工具，可以处理多种格式的内存转储，包括：

- 原始/填充物理内存
- Firewire (IEEE 1394)
- Expert Witness (EWF)
- 32位和64位Windows崩溃转储
- 32位和64位Windows休眠文件
- 32位和64位MachO文件
- Virtualbox核心转储
- VMware保存状态(.vmss)和快照(.vmsn)
- HPAK格式(FastDump)
- LiME(Linux内存提取器)
- QEMU虚拟机内存转储

每次内存采集后，您需要生成内存采集的MD5哈希值以**确保完整性**。 完整性在整个内存取证过程中至关重要。 多个方可能会分析内存采集，这可能会引入不必要的更改，污染其取证价值。 因此，您应始终创建内存采集的副本，并使用该副本进行分析。 您可以使用哈希来确保副本与原始文件完全相同。

### 完整内存采集

转到虚拟机，导航到桌面，双击FTK imager图标以启动FTK imager工具。

现在按照以下步骤进行内存采集：

- 点击文件 => 捕获内存
- 输入保存内存采集的目标路径。 理想情况下，这应该是一个具有足够磁盘空间以容纳内存采集的外部存储设备。 对于本练习，请给出路径`C:\Users\administrator\Documents\完整内存采集`
- 为采集文件指定一个合适的名称。 理想情况下，您应使用IR手册中内存流程大纲定义的模式。 对于本练习，您可以使用`主机名_日期.mem`格式作为文件名：`FS-ANALYSIS_2025年4月7日.mem`
- 选择是否包含页面文件。 **注意：页面文件可能很大，具体取决于您的系统配置**
- 点击`捕获内存`

![Windows完整内存转储](img/66c44fd9733427ea1181ad58-1744118959741.gif)

过程完成后，您需要确保捕获文件的完整性：

- 以管理员身份打开PowerShell窗口
- 输入`Get-FileHash`命令及所需参数，如下方终端所示。 根据您选择的算法，生成哈希可能需要几分钟。 您的内存流程大纲还应定义使用哪种哈希算法
- 记下哈希值。 应在您的内存流程大纲中描述记录位置。 `注意：此示例与您的计算哈希值将不同，这是预期的，因为内存内容不断变化`

```shell title="Full Memory Capture - Hash"
PS C:\Users\Administrator\Documents> Get-FileHash -Path 'C:\Users\Administrator\Documents\Full Memory Capture\FS-ANALYSIS-07April2025.mem' -Algorithm MD5 

Algorithm Hash Path

MD5 42CD44244B8ED77CCF89ECAA6C3F957A C:\Users\Administrator\Documents\Full Memory Capture\FS-ANALYSIS-07April2025.mem
```

### 进程内存转储

继续使用虚拟机，以管理员权限打开新的PowerShell终端，并导航到路径`C:\TMP\SysinternalsSuite\`。

SysInternals套件包含一个名为`procdump64.exe`的工具，您可以使用它来转储选定进程的内存内容。 您可以手动执行此操作，也可以基于**触发器**（如高CPU使用率）执行。

您将专注于手动转储`lsass.exe`进程。 此进程管理身份验证、令牌、凭据等。 威胁行为者通常使用**Mimikatz**针对`lsass.exe`进程。 输入以下命令以转储`lsass.exe`进程的内容：

```shell title="Process Dump"
PS C:\TMP\SysinternalsSuite> .\procdump64.exe -ma lsass.exe C:\TMP -accepteula

ProcDump v11.0 - Sysinternals process dump utility

Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards

Sysinternals - www.sysinternals.com

[13:45:44] Dump 1 initiated: C:\TMP\lsass.exe_250408_134544.dmp

[13:45:44] Dump 1 writing: Estimated dump file size is 47 MB.

[13:45:44] Dump 1 complete: 47 MB written in 0.5 seconds

[13:45:45] Dump count reached.
```

仔细查看命令中包含的选项：

- `-ma`：此标志设置转储类型以包含进程的完整内存内容。 默认选项是小型转储(`-mm`)，仅包含进程的基本信息。 小型转储对于崩溃很有用，但不适用于恶意软件分析或提取凭据。 还有其他可用的标志。 使用`.\procdump.exe -h`命令显示它们
- `lsass.exe`：这是您将转储内存的进程
- `C:\TMP`：内存转储保存在此目录中

文件转储的默认名称是`进程名_年月日_时分秒.dmp`。 对于本练习，您可以保留此名称。 通常，您会调整名称以匹配IR手册中内存大纲的内容。

现在您已创建`lsass.exe`进程的内存转储，需要确保其完整性。 输入以下命令计算内存采集的MD5哈希值。 调整文件名以反映您的内存采集。

```shell title="Calculate Hash"
PS C:\TMP\SysinternalsSuite>  Get-FileHash -Path 'C:\TMP\lsass.exe_250408_082640.dmp' -Algorithm MD5
Algorithm Hash Path       
MD5 9DF3963A62B01D3151CB6B824C8DE6D1 C:\TMP\lsass.exe_250408_082640.dmp
```

### 崩溃转储

Windows包含配置选项，用于确定崩溃时应执行的操作。 这些选项决定是否进行内存转储、转储类型、保存位置以及是否覆盖现有内存转储。

从取证角度来看，系统崩溃的内存转储也是可用的信息。 例如，恶意进程可能导致系统崩溃。 按照以下步骤配置系统故障后的内存转储。

- 右键单击任务栏中的Windows徽标，然后单击`运行`
- 输入`sysdm.cpl`以打开`系统属性`控制面板项
- 导航到`高级`选项卡，在`启动和恢复`部分下单击`设置...`
- 在`系统故障`-`写入调试信息`部分配置内存转储。 选择哪种转储将取决于您的用例。

![内存转储选项](img/66c44fd9733427ea1181ad58-1744030888437.gif)

:::info 回答以下问题

<details>

<summary> 在虚拟机上启动notepad.exe，并使用procdump64.exe工具写入进程的'triage'转储文件。 确保转储文件的名称格式为进程名_PID_年月日_时分秒.dmp。 在下方输入完整命令。 注意：使用PowerShell以确保语法正确。 无需包含`-accepteula`标志</summary>

```plaintext
.\procdump64.exe -mt notepad.exe PROCESSNAME_PID_YYMMDD_HHMMSS.dmp
```

</details>

<details>

<summary> 哪两个工具可用于提取或转储lsass.exe进程的内存工件？ 按字母顺序输入答案，并用逗号分隔。 例如：volatility,procmon.exe</summary>

```plaintext
mimikatz,procdump64.exe
```

</details>

<details>

<summary> 在继续下一个任务之前，关闭虚拟机电源。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务4 Linux内存采集

### 简介

在Linux主机上采集内存是一个简单的过程。 您需要决定与Windows主机相同的步骤。

在此任务期间，您将专注于业务时间内的以下内存采集：

- 使用`LiME`工具进行完整内存采集
- 使用`GNU调试器`的一部分`gcore`工具进行进程内存转储
- 配置Ubuntu在系统崩溃时生成内存转储

与之前的任务类似，您需要确保与`volatility`的兼容性。 每次内存捕获后，您需要生成内存捕获的MD5哈希值以确保完整性。

### 完整内存采集

在此任务中，您将使用`LiME`工具进行完整内存捕获。 大多数Linux系统默认不包含此工具。 由于虚拟机无法访问互联网，**我们已为您预安装了该工具**。 如果您在自己的机器上尝试，以下是手动安装的方法：

```shell title="Install LiME"
ubuntu@tryhackme:~$
# first install necessary dependencies
sudo apt update
sudo apt install -y git build-essential linux-headers-$(uname -r)
# Clone the LiME repository
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
# compile LiME for use in kernel
make
```

继续使用虚拟机，打开终端窗口并输入以下命令以进行完整内存捕获：

```shell title="Take Memory Dump"
ubuntu@tryhackme:~$ cd LiME/src
ubuntu@tryhackme:~/LiME/src$ sudo insmod lime-6.8.0-1027-aws.ko "path=/tmp/ubuntu-150000-22042025.lime format=lime"
```

让我们仔细查看命令中包含的选项：

- `sudo insmod lime-6.8.0-1027-aws.ko`：`insmod`命令在内核中加载LiME工具（`lime.ko`）。 这是必要的，以便LiME可以进行完整内存捕获
- `path=/tmp/ubuntu-150000-22042025.lime`：这是保存内存转储的目录和内存转储的名称。 使用的命名模板是`HOSTNAME-HHMMSS-DDMMYYYY.lime`。 您可以根据需要更改名称
- `format=lime`：此命令将内存转储的格式设置为`.lime`。 确保这与您的内存分析工具兼容

如果您想更改上述任何参数或包含其他参数，可以参考LiME工具的[官方GitHub](https://github.com/504ensicsLabs/LiME)上的帮助页面。

过程完成后，您需要确保捕获文件的完整性并**卸载LiME工具**：

- 输入命令`md5sum`并带上所需的参数，如下方终端所示。 根据您选择的算法，生成哈希可能需要几分钟。 您的内存流程大纲还应定义使用哪种哈希算法
- 记下哈希值。 应在您的内存流程大纲中描述记录位置。 **注意：此示例与您计算的哈希值会有所不同，这是预期的，因为内存内容不断变化**
- 最后输入`sudo rmmod lime`命令以从内核中卸载LiME。 **注意：每次您想捕获内存时，必须先运行此命令以卸载任何先前的LiME模块**

```shell title="MD5 Hash"
ubuntu@tryhackme:~/LiME/src$ md5sum tmp/ubuntu-150000-22042025.lime
0ef7140f0c0cabd6c4ef76c708f2324f  /tmp/ubuntu-150000-22042025.lime

ubuntu@tryhackme:~/LiME/src$ sudo rmmod lime
```

### 进程内存转储

继续使用虚拟机，打开新终端并输入以下命令以转储`bash`进程的内存：

```shell title="Process Dump with gcore"
ubuntu@tryhackme:~$ ps aux |grep bash # Search the PID number of the bash process
ubuntu      6506  0.0  0.2   5892  4096 pts/0    Ss   Apr11   0:00 bash
ubuntu     34136  0.0  0.1   3528  1792 pts/0    S+   13:57   0:00 grep --color=auto bash

ubuntu@tryhackme:~$ sudo gcore -o /tmp/BASH-130000-10042025 6506 # Dump the memory of the bash process using gcore
```

现在您已创建了`bash`进程的内存转储，需要确保其完整性。 输入以下命令计算内存采集的MD5哈希值。 调整文件名以反映您的内存采集。

```shell title="Process Dump with gcore"
ubuntu@tryhackme:~$ md5sum /tmp/BASH-130000-10042025.6506 
b1baa84b8f1e725f1a45795465ba710c  /tmp/BASH-130000-10042025.6506
```

### 崩溃转储

与Windows类似，您可以配置Linux在进程或内核崩溃时进行内存转储。 然而，配置不像Windows那样直接。 这将取决于主机的发行版类型和内核。

#### 内核崩溃转储

如Ubuntu**官方文档**所述，从Ubuntu版本24.10开始，内核崩溃转储默认启用。 此任务中的虚拟机是Ubuntu版本24.04，因此您必须自己启用内核崩溃转储。 由于虚拟机的连接有限，**我们已自行完成配置**。 我们输入了以下命令并在下方终端窗口中添加了说明性注释（使用#分隔符）：

```shell title="Enable kdump"
ubuntu@tryhackme:~$ 
# check status kernel crash dump utility
ubuntu@tryhackme:~$ cat /proc/cmdline # This command verifies if the kernel crash dump is enabled or not. If a line similar to 'crashkernel=384M-2G:64M,2G-:128M' is present, it is enabled. You don't need to execute the following commands in this case.

# Install kdump (This is the kernel crash dump utitlity)
ubuntu@tryhackme:~$ sudo apt install kdump-tools -y

# Reboot to enable the kdump tool
ubuntu@tryhackme:~$ sudo -reboot

# Verify if the kdump tool is running
ubuntu@tryhackme:~$ sudo kdump-config show # You can enter this command yourself on the VM
DUMP_MODE: kdump
USE_KDUMP: 1 # 1 means that kdump is in use
KDUMP_COREDIR: /var/crash
crashkernel addr: 0x69000000
/var/lib/kdump/vmlinuz: symbolic link to /boot/vmlinuz-6.8.0-1027-aws
kdump initrd:
/var/lib/kdump/initrd.img: symbolic link to /var/lib/kdump/initrd.img-6.8.0-1027-aws
current state: ready to kdump # kdump is able to dump
crashkernel suggested size: 371M
kexec command:
/sbin/kexec -p --command-line="BOOT_IMAGE=/boot/vmlinuz-6.8.0-1027-aws root=PARTUUID=da63a61e-01 ro console=tty1 console=ttyS0 nvme_core.io_timeout=4294967295 panic=-1 reset_devices systemd.unit=kdump-tools-dump.service nr_cpus=1 irqpoll usbcore.nousb" --initrd=/var/lib/kdump/initrd.img /var/lib/kdump/vmlinuz
```

#### 进程崩溃转储

在大多数Linux发行版上，进程崩溃转储默认禁用。 根据Linux风格，有不同的方法启用自动或部分崩溃转储。

在此任务中，您将专注于虚拟机正在运行的Ubuntu Desktop。 要覆盖Ubuntu Desktop上的所有进程，您需要配置2个选项：

- systemd管理进程的崩溃转储
- 交互式会话和用户进程的崩溃转储

首先输入以下命令以配置systemd管理进程的崩溃转储：

```shell title="Process crash dump"
ubuntu@tryhackme:~$ sudo mkdir -p /etc/systemd/system.conf.d
ubuntu@tryhackme:~$ sudo nano /etc/systemd/system.conf.d/core-dumps.conf
# Add the following lines to the core-dumps.conf file and enter CTRL+o to save the file, then exit the editor by entering CTRL+x
[Manager]
DefaultLimitCORE=infinity

# Now reload the systemd service
ubuntu@tryhackme:~$ sudo systemctl daemon-reexec
```

现在，继续配置用户进程和交互式会话的崩溃转储。 以下命令将确保配置持久化。 输入以下命令：

```shell title="Process crash dump"
# Enable process dumps
ubuntu@tryhackme:~$ ulimit -c unlimited

# Open the config file
ubuntu@tryhackme:~$ sudo nano /etc/sysctl.d/60-core-pattern.conf

#Add the following lines to set naming template
kernel.core_pattern = /var/crash/core.%e.%p.%t
fs.suid_dumpable = 1

# Create the /var/crash folder and assign permissions if it does not exist yet
ubuntu@tryhackme:~$ sudo mkdir -p /var/crash
ubuntu@tryhackme:~$ sudo chmod 1777 /var/crash
```

上述方法适用于Ubuntu Desktop和Server版本。

Ubuntu Desktop还默认启用了一个名为`apport`的崩溃转储实用程序。 此服务捕获崩溃进程的核心转储，决定是否对其采取行动，然后创建一个`.crash文件`，其中包括：

- 堆栈跟踪
- 进程信息
- 加载的库
- 部分内存内容，非完整核心转储

崩溃文件保存在`/var/crash`目录中。

:::info 回答以下问题

<details>

<summary> 修改以下命令以确保内存转储为.raw格式且可通过TCP端口5555访问：`sudo insmod lime-6.8.0-1027-aws.ko "path=/tmp/memdump.lime format=lime"` </summary>

```plaintext
sudo insmod lime-6.8.0-1027-aws.ko "path=tcp:5555 format=raw"
```

</details>

<details>

<summary> LiME包含一个参数可在捕获内存后立即创建哈希值。 修改以下命令并确保计算MD5哈希值：`sudo insmod lime-6.8.0-1027-aws.ko "path=/tmp/memdump.lime format=lime"` </summary>

```plaintext
sudo insmod lime-6.8.0-1027-aws.ko "path=/tmp/memdump.lime format=lime digest=md5"
```

</details>

:::

## 任务5 虚拟机和云环境中的内存获取

与之前的两个任务类似，您必须就内存获取过程做出一些决定。 对于此任务，您将专注于在正常工作时间从Hypervisor和云平台获取内存转储。
然后您将为正确的工作选择正确的工具或方法。 有两种方法可以从Hypervisor和云平台获取内存：

- 登录虚拟机并使用之前任务中看到的技术
- 使用Hypervisor或云平台的内置工具提取内存，而不直接与虚拟机交互。 这可以通过GUI或命令行完成

在此任务中，您将尽可能专注于第二种方法。 您将学习在最常见的Hypervisor和云平台上获取内存转储的方法，包括：

- Microsoft Hyper-V
- VMware vSphere
- VirtualBox
- KVM
- 云平台

您将专注于提供与`volatility`兼容的内存转储。

### 在Hypervisor上获取内存转储

从托管的虚拟机获取内存转储的方法对于每种Hypervisor风格都类似。

**首先**，您需要拍摄快照或暂停虚拟机。 **然后**，您可以复制每个Hypervisor在拍摄快照或暂停虚拟机时创建的内存状态文件。 根据Hypervisor的风格，您可能需要转换内存状态文件以与`volatility`兼容。

**注意：有其他方法可以获取内存。 此任务将专注于在可用时使用内置工具和/或实用程序。**

#### Microsoft Hyper-V

在Hyper-V托管的虚拟机上获取内存可以使用Hyper-V的本机功能完成。 您可以选择使用GUI或PowerShell命令行。 下方终端显示了使用PowerShell的过程。 GUI和PowerShell的步骤基本相同：

- 通过GUI或PowerShell cmdlet（`Checkpoint-VM`或`Save-VM`）保存虚拟机或创建检查点
- 导航到快照存储位置并复制包含RAM内容的`.vmrs`文件
- 计算哈希值以确保后续分析内存转储时的完整性
- 使用`volatility windows.hyperv`插件处理文件

```shell title="Memory dump Hyper-v"
PS C:\Users\administrator> get-vm | FT VMId, VMName

VMId VMName
c5f1b464-ffea-4904-bc7b-974c74b10159 Ubuntu 22.04 LTS<
PS C:\Users\administrator> get-vm -Id c5f1b464-ffea-4904-bc7b-974c74b10159 | Checkpoint-VM
PS C:\Users\administrator> Get-VMSnapshot -VMName 'Ubuntu 22.04 LTS' |FT Id,Name,Path
PS C:\Users\administrator> cp C:\ProgramData\Microsoft\Windows\Hyper-V\Snapshots\97DBBAE5-3F91-4E5E-B177-FBB970E8703E.VMRS C:\temp\hostname-17-04-2025.VMRS
PS C:\Users\administrator> Get-FileHash -Algorithm MD5 -Path C:\temp\hostname-17-04-2025.VMRS
Algorithm Hash Path
MD5           E1BA77075C7C832CC96E43DB8E8F98E8   C:\temp\hostname-17-04-2025.VMRS
```

#### vSphere

在`vSphere`中，您可以使用内置工具（vCenter服务器+vSphere客户端）拍摄虚拟机的快照。 您可以使用GUI或ESXCLI工具。 获取内存的步骤类似：

- 拍摄虚拟机的快照
- 导航到虚拟机所在的数据存储并复制`.vmsn文件`
- 计算哈希值以确保完整性
- `volatility`支持处理`.vmsn文件`，因此您无需转换它们

![vCenter GUI中的内存转储](img/66c44fd9733427ea1181ad58-1745337491450.gif)

#### KVM

获取托管在KVM上的虚拟机内存转储的最简单方法是使用命令行实用程序。 步骤与其他Hypervisor类似：

- 首先，找到虚拟机的名称。 使用`virsh list`命令列出所有虚拟机
- 然后，通过输入`virsh dump vmname /path/to/dupm.raw --memory-only`来转储虚拟机的内存
- 最后，创建内存转储文件的哈希`md5sum memdump.raw`

#### VirtualBox

获取托管在VirtualBox上的虚拟机内存的推荐方法是使用`VBoxManage`工具。 在Windows安装中，您可以在Virtualbox的安装路径中找到此命令行实用程序，例如 `C:\Program Files\Oracle\VirtualBox`。 按照以下步骤获取虚拟机的内存转储：

- 列出正在运行的虚拟机并找到虚拟机的名称
- 使用`debugvm`命令进行转储
- 计算哈希值以确保后续分析过程中文件的完整性
- `Volatility`支持处理`.elf文件`，因此您无需转换它们

```shell title="Memory Dump"
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe list runningvms
"Kali_purple" {9a969c90-7ab0-4b9b-893d-48c70fa42ee5}
PS C:\Program Files\Oracle\VirtualBox> .\VBoxManage.exe debugvm "Kali_purple" dumpvmcore --filename C:\temp\kali_memdump.elf
PS C:\Program Files\Oracle\VirtualBox> Get-FileHash -Algorithm MD5 -Path C:\temp\kali_memdump.elf
Algorithm Hash Path
MD5             1833B5B07C8E43A6E011919934AFB049           C:\temp\kali_memdump.elf
```

### 在云平台上获取内存转储

与Hypervisor不同，从托管在Azure或AWS等云平台上的虚拟机获取内存转储的过程并不直接。 这两个平台都没有内置工具来支持获取内存转储。 在这种情况下，您将无法避免直接与虚拟机交互。 云提供商不提供此工具的主要原因之一是硬件资源的共享性质。

从托管在云平台上的虚拟机获取内存转储的推荐方法是遵循我们在任务三和四中讨论的特定于每个操作系统的步骤。

然而，在某些场景中会使用一种替代方法。 此方法涉及以下步骤：

- 在主机上配置完整内存崩溃转储
- 通过云平台触发手动崩溃
- 分离保存崩溃转储的磁盘
- 将磁盘作为只读数据磁盘连接到同一或不同租户内托管的分析虚拟机。
- 额外步骤：导出磁盘以便可以在不同租户中使用

#### 特别提及Azure

Microsoft发布了一个名为Acquire Volatile Memory for Linux（AVML）的工具，以简化在Azure上托管的虚拟机上获取易失性内存的过程。 此工具的主要优势之一是它不需要任何安装或内核加载。 它可以作为独立二进制文件运行。 **注意：该工具仅用于在Linux发行版上获取内存。**

### 结论

在本任务中，您学习了如何在Windows主机、Linux主机、托管在Hypervisor上的虚拟机以及托管在Hypervisor或云平台上的虚拟机上捕获内存。 您注意到了多种获取内存转储的方法，无论是通过GUI还是命令行实用程序。 最后，您观察到云平台不提供任何内置工具来在不与虚拟机交互的情况下获取内存转储。

获取内存转储并非高深莫测，但前几个任务中提到了一些需要考虑的事项：

- 时机
- 确保您在目标主机上拥有管理员权限
- 使用适合您需求的工具
- 为内存转储定义适当的命名约定
- 通过哈希确保完整性
- 记录文件名及其哈希值，以便后续参考
- 确保以上所有内容都是您IR手册中流程大纲的一部分

:::info 回答以下问题

<details>

<summary> 在VirtualBox Hypervisor上获取内存转储时使用的命令行实用程序名称是什么？ 使用格式filename.extension进行回答。 </summary>

```plaintext
vboxmanage.exe
```

</details>

<details>

<summary> 在Hyper-V中创建快照使用哪个命令？ </summary>

```plaintext
CheckPoint-VM
```

</details>

:::

## 任务6 内存获取的挑战

内存获取确实带来了一些挑战。 在开始内存获取过程之前，请考虑以下困难：

- **反取证技术**：攻击者可以采用反取证技术来阻碍正常的内存获取。 例如，加密内存内容、干扰获取工具等
- **时机**：在获取内存时，把握正确的时机至关重要。 如任务二所述，内存是易失性的，其内容不断变化。 密切关注攻击和入侵指标以选择正确的时机
- **（物理）可访问性**：要进行内存捕获，您需要本地或远程访问系统。 有时，服务器位于未经适当验证无法访问的数据中心。 确保正确的人员拥有正确的访问权限
- **无管理员权限**：要进行完整的内存捕获，您必须拥有管理员权限。 这可以是主机级别、域级别或云平台中的资源组级别
- **缺乏信息安全管理体系（ISMS）**：在考虑取证之前，您必须建立适当的ISMS。 ISMS的一个重要部分是**资产管理**，它列出了内存获取所需的基本信息。 它帮助您了解每个资产的：
  - 详细信息（主机名、IP、操作系统、用户、物理位置）
  - 关键性
  - 运行时间
  - 基线配置
  - 基线行为
  - 以及其他
- **缺乏透明的应急响应流程**：未能考虑任务二中的所有主题将阻碍您进行正确的内存获取。 确保将内存获取流程纳入您的应急响应计划中

:::info 回答以下问题

<details>

<summary> 哪个流程描述了跟踪所有主机及其信息？ </summary>

```plaintext
Asset Management
```

</details>

<details>

<summary> 威胁行为者在成功窃取数据后关闭了目标系统。 我们可以使用什么术语来对此行为进行分类？ </summary>

```plaintext
anti-forensic techniques
```

</details>

:::

## 任务 7 结论

正如您所发现的，完成本房间的所有任务后，获取符合取证要求的内存转储远不止表面看起来那么简单。 您了解到在进行内存转储之前需要考虑多个因素：

- 捕获内存的哪部分
- 何时捕获内存
- 如何捕获内存

您学习了如何从Ubuntu、Windows、Hypervisor和云平台获取各种内存转储。 您以内存获取的各种挑战概述结束了本房间。

既然您已经知道如何获取内存，下一步就是分析它。 继续学习本模块的下一个房间，了解如何使用`volatility`等工具分析内存转储。

:::info 回答以下问题

<details>

<summary> 准备好应用您的新技能了吗？ </summary>

```plaintext
No answer needed
```

</details>

:::
