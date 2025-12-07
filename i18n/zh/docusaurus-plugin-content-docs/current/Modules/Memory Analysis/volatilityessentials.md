---
sidebar_position: 2
---

# Volatility基础

## 任务 1 介绍

在之前的房间[内存分析简介](https://tryhackme.com/room/memoryanalysisintroduction)中，我们了解了内存取证在网络安全中的关键性质。 我们探讨了内存转储的结构，区分了RAM和磁盘取证，并看到了内存分析至关重要的场景。

在这里，我们将开始通过工具（特别是Volatility）来了解内存取证的实践方面。

### 学习目标

- 熟悉Volatility框架
- 导航并使用基本的Volatility命令和插件
- 使用Volatility进行取证分析，以识别关键工件，如运行进程和加载的DLL

### 先决条件

- [内存分析简介](https://tryhackme.com/room/memoryanalysisintroduction)
- [核心Windows进程](https://tryhackme.com/room/btwindowsinternals)

:::info 回答以下问题

<details>

<summary> 准备好学习Volatility和内存分析。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务2 Volatility概述

[Volatility](https://volatilityfoundation.org/the-volatility-framework/)是一个开源的、跨平台、模块化且可扩展的内存取证框架。 该框架多年来经历了多次迭代，当前版本为Volatility 3。 此版本优于其前身，因为它放弃了静态操作系统分析，转而采用动态符号解析，支持更新的操作系统、内存布局，并完全洞察系统的运行时状态。

### 架构概述

Volatility 3由几个关键层组成：

- **内存层**：这些层表示地址空间的层次结构，从原始内存到虚拟地址转换。
- **符号表**：这些表通过操作系统特定的调试符号来解释内核和进程结构。
- **插件**：这些是模块化例程，利用底层内存层和符号表来提取取证感兴趣的工件。 稍后在房间中，我们将查看一些关键插件。

### 系统要求和安装

Volatility 3需要Python 3.6或更高版本才能运行。 此外，它受益于各种库，如`pefile`、`capstone`和`yara-python`，这些库允许我们分别处理可移植可执行文件、执行内存反汇编并在分析中使用YARA规则。 下面的终端输出显示了如何通过克隆[GitHub仓库](https://github.com/volatilityfoundation/volatility3.git)并从源代码直接运行来安装Volatility。

Volatility已安装在此房间连接的机器上，可在`Desktop/volatility3`目录下访问。

```shell title="Volatility Installation"
ubuntu@tryhackme:~/Desktop$ git clone https://github.com/volatilityfoundation/volatility3.git
ubuntu@tryhackme:~/Desktop$ cd volatility3
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -h
Volatility 3 Framework 2.26.2
usage: vol.py [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q]
              [-r RENDERER] [-f FILE] [--write-config] [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline | -u URL]
              [--filters FILTERS] [--hide-columns [HIDE_COLUMNS ...]] [--single-location SINGLE_LOCATION] [--stackers [STACKERS ...]]
              [--single-swap-locations [SINGLE_SWAP_LOCATIONS ...]]
              PLUGIN ...

An open-source memory forensics framework

options:
  -h, --help            Show this help message and exit, for specific plugin options use 'vol.py  --help'
  -c CONFIG, --config CONFIG
                        Load the configuration from a json file
------TRUNCATED--------
```

:::info 回答以下问题

<details>

<summary> 阅读以上内容并导航到Volatility目录。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务3 内存获取和分析

### 内存获取方法

内存取证是取证中的一个基础步骤，必须以确保我们保持证据完整性的方式执行。 所使用的流程和部署环境因操作系统而异。

对于Windows系统，可以使用以下工具进行内存获取：

- **DumpIt**：在32/64位Windows上捕获完整的物理内存镜像，并自动对输出进行哈希处理。
- **WinPmem**：基于驱动的开源工具，以RAW/ELF格式获取RAM，并嵌入获取元数据以用于证据链。
- **Magnet RAM Capture**：GUI驱动的收集器，在实时Windows主机上快照易失性内存，同时最小化占用空间。
- **FTK Imager**：最常见的商业工具，在磁盘镜像功能的同时获取内存和选定的逻辑工件。

对于Linux和macOS系统，我们可以使用以下工具的服务：

- **AVML**：轻量级Microsoft CLI实用程序，将Linux内存转储到压缩的ELF文件中，无需内核模块。
- **LiME**：Linux的可加载内核模块，通过磁盘或网络捕获完整的易失性内存，并支持ARM/x86架构。
- **OSXPmem**：macOS特定的Pmem分支，在基于Intel的Mac上创建原始内存镜像，用于后续的Volatility分析。

从虚拟环境中提取内存可以通过从主机驱动器中收集虚拟内存文件来完成。 根据所使用的虚拟机管理程序，输出文件可能会有所不同，您可能会遇到以下示例：

- VMware - `.vmem`
- Hyper-V - `.bin`
- Parallels - `.mem`
- VirtualBox - `.sav` 值得注意的是，这是一个部分内存文件。

### 内存分析

为了全面且实践性地理解Volatility，我们将调查一个取证案例，并使用它来了解该工具的内部工作原理。 分析文件位于`Desktop/Investigations`目录下。

#### 案例001

您的SOC通知您，他们已从一个隔离的端点收集了内存转储，该端点被认为已被伪装成Adobe文档的银行木马感染。 您的任务是利用威胁情报和逆向工程知识，对受感染主机进行内存取证。

您已被告知一个与文件`Investigation-1.vmem`相关的可疑IP，可能有用：`41.168.5.140`。

#### 插件

Volatility使用插件来请求数据以进行分析。 一些最常用的插件包括：

- `windows.info`
- `linux.info`
- `pslist`
- `pstree`

让我们查看这些插件，从我们的内存文件中提取信息。 首先，我们可以从获取镜像中的操作系统详细信息开始。 在Volatility的先前版本中，此信息被识别为**操作系统配置文件**，并使用插件`imageinfo`提取。 然而，操作系统配置文件在新版本中已被弃用，现在我们有了单独的信息插件。

鉴于我们的内存文件是从运行在VMware上的Windows虚拟机获取的，我们可以使用以下命令提取其配置文件的详细信息：

```shell title="Volatility Windows Info"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.info
Volatility 3 Framework 2.26.2
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Investigation-1.vmem and Investigation-1.vmss.
Progress:  100.00               PDB scanning finished                                                                                              
Variable        Value

Kernel Base     0x804d7000
DTB     0x2fe000
Symbols file:///home/ubuntu/Desktop/volatility3/volatility3/symbols/windows/ntkrnlpa.pdb/30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz
```

我们可以从详细信息中提取系统版本、架构、符号表和可用的内存层。

:::info 回答以下问题

<details>

<summary> 案例001中主机机器的构建版本是什么？ </summary>

```plaintext
2600.xpsp.080413-2111
```

</details>

<details>

<summary> 案例001中内存文件是在什么时间获取的？ </summary>

```plaintext
2012-07-22 02:45:08
```

</details>

:::

## 任务4 列出进程和连接

当我们想要分析内存文件中进程和网络连接的详细信息时，Volatility支持不同的插件，每个插件使用不同的技术。 并非此处提到的所有插件都会从内存文件中产生结果，因为捕获可能未包含插件将枚举的进程或服务。

### 活动进程枚举

列出进程的最基本方法是使用`pslist`。 此插件从跟踪内存中进程的双向链表中枚举活动进程，相当于任务管理器中的进程列表。 此插件的输出将包括所有当前和已终止的进程及其退出时间。

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.pslist
```

### 隐藏进程枚举

一些恶意软件（通常是rootkit）会尝试隐藏其进程，从列表中取消链接自身。 通过从列表中取消链接自身，使用`pslist`时将不再看到它们的进程。 为了对抗这种规避技术，我们可以使用`psscan`。 这种列出进程的技术将通过查找匹配`_EPROCESS`的数据结构来定位进程。 虽然这种技术可以帮助对抗规避措施，但也可能导致误报；因此，我们必须小心。

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.psscan
```

### 进程层次枚举

第三个进程插件`pstree`不提供任何其他特殊技术来帮助识别规避，如最后两个插件。 然而，此插件将根据其父进程ID列出所有进程，使用与`pslist`相同的方法。 这对于分析师获取进程的完整情况以及提取时可能发生的情况非常有用。

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.pstree
```

### 文件、注册表和线程枚举

在内存取证调查期间，检查文件和注册表也至关重要。 我们可以使用 `handles` 插件来查看主机中文件和线程的详细信息及句柄。

```shell title="Volatility Files Inspecting"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.handles
```

### 网络连接枚举

既然我们知道了如何识别进程，我们也需要一种方法来识别主机提取时存在的网络连接。 `netstat` 将尝试识别所有具有网络连接的内存结构。

```shell title="Volatility Network  Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.netstat
```

值得注意的是，在 Volatility 3 的当前状态下，此命令可能非常不稳定，尤其是在旧的 Windows 构建版本中。 为了解决这个问题，你可以使用其他工具，如 [bulk_extractor](https://tools.kali.org/forensics/bulk-extractor)，从内存文件中提取 PCAP 文件。 有时，对于无法仅从 Volatility 识别的网络连接，这更可取。

### TCP/UDP 套接字枚举

我们还可以从内存文件中识别网络套接字及其关联的进程。 为此，我们可以使用 `netscan` 插件。 这将通过内存池扫描恢复活动和已关闭的 TCP/UDP 连接、关联的进程 ID、本地和远程端口以及 IP。

```shell title="Volatility TCP/UDP Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.netscan
```

### DLL 枚举

我们将介绍的最后一个插件是 `dlllist`。 此插件将列出提取时与进程关联的所有 DLL。 一旦你进一步分析并将输出过滤到可能指示你认为系统上存在的特定类型恶意软件的特定 DLL 时，这可能特别有用。

```shell title="Volatility DLL Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.dlllist
```

:::info 回答以下问题

<details>

<summary> 活动 Adobe 进程的绝对路径是什么？ </summary>

```plaintext
C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe
```

</details>

<details>

<summary> 在案例 001 中，此进程的父进程是什么？ </summary>

```plaintext
explorer.exe
```

</details>

<details>

<summary> 父进程的 PID 是什么？ </summary>

```plaintext
1484
```

</details>

<details>

<summary> Adobe 进程使用了多少个位于 `system32` 目录之外的 DLL 文件？ </summary>

```plaintext
3
```

</details>

<details>

<summary> 与进程句柄关联的一个 KeyedEvent 的名称是什么？ </summary>

```plaintext
CritSecOutOfMemoryEvent
```

</details>

:::

## 任务5 Volatility 狩猎与检测能力

高级威胁可以仅在内存中执行，避免磁盘痕迹。 Volatility 提供了许多插件，可以在狩猎注入代码和恶意软件时，以及通过 YARA 应用自定义检测规则时，帮助提升你的狩猎和检测能力。

在阅读本节之前，建议你对对手如何采用规避技术和各种恶意软件技术，以及如何狩猎和检测它们有基本的了解。

### 恶意软件分析

我们将讨论的第一个插件是 `malfind`，它是狩猎代码注入时最有用的插件之一。 此插件将尝试检测注入的进程及其 PID，以及偏移地址和感染区域的十六进制、ASCII 和反汇编视图。 该插件通过扫描堆并识别设置了可执行位 **RWE** 或 **RX** 和/或磁盘上没有内存映射文件（无文件恶意软件）的进程来工作。

根据 `malfind` 识别的内容，注入的区域会发生变化。 MZ 头是 Windows 可执行文件的指示器。 注入的区域也可能指向需要进一步分析的 shellcode。

![Windows 可执行文件的文件结构，显示 MZ 头值。](img/image_20251207-210748.png)

```shell title="Volatility Malware Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.malfind
```

另一个有用的插件是 `vadinfo`。 这显示了虚拟内存描述符的详细信息，在手动调查可疑内存区域和堆分配时非常有用。

```shell title="Volatility Malware Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.vadinfo
```

:::info 回答以下问题

<details>

<summary> 案例 001 内存文件中的哪些进程包含指向 Windows 可执行文件的头？ (答案: process1,process2) </summary>

```plaintext
explorer.exe,reader_sl.exe
```

</details>

:::

## 任务6 高级内存取证

取证分析师在处理诸如内核模式 rootkit 等复杂威胁时，必须能够检测操作系统深处的操纵。 Rootkit 旨在通过修改内核结构来隐藏进程、文件、驱动程序及其存在。 本节重点使用 Volatility 3，对这些高级规避技术，特别是在 Windows 操作系统内，进行结构化和实践性的探索。

高级对手经常采用 **挂钩** —— 一种允许恶意软件拦截并可能重定向系统级功能以实现规避或持久性的技术。 挂钩本身并非恶意；防病毒和调试工具也合法地使用它们。 分析师的责任是识别挂钩的存在是否符合预期的系统行为，还是代表恶意干扰。

最常见的挂钩策略之一是 **系统服务描述符表 (SSDT)** 挂钩。 这些挂钩用于修改内核系统调用表条目。 它们在内核模式恶意软件中很普遍，Volatility 提供了相应的插件进行分析。

### SSDT 挂钩检测

Windows 内核使用 **系统服务描述符表 (SSDT)** 来解析系统调用的地址。 Rootkit 经常覆盖 SSDT 条目，将合法的系统调用（例如 `NtCreateFile`）重定向到其恶意对应项。

Volatility 3 的 `windows.ssdt` 插件使分析师能够检查此表是否存在任何异常。

```shell title="Volatility SSDT Hook Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.ssdt
```

**建议**：在发现可疑内核模块或异常进程行为 **之后** 执行 SSDT 检查。

### 内核模块枚举

`windows.modules` 插件列出了当前加载到内存中的驱动程序和内核模块。 每个条目包括基地址、大小和文件路径等元数据。

```shell title="Volatility Kernel Module Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.modules
```

### 驱动程序扫描

虽然 `windows.modules` 列出了已知的驱动程序，但它可能会遗漏隐藏或未链接的驱动程序。 `windows.driverscan` 插件扫描原始内存中可能已从标准列表中取消链接的 DRIVER_OBJECT 结构。

```shell title="Volatility Kernel Module Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.driverscan
```

**提示**：如果你怀疑 DKOM（直接内核对象操纵）或 rootkit 行为，请使用此插件。

:::info 回答以下问题

<details>

<summary> `NtCreateFile` 系统调用的地址是什么？ </summary>

```plaintext
0x8056e27c
```

</details>

:::

## 任务7 实践调查

### 案例 002

你被告知你的公司遭受了一系列影响国际公司的勒索软件攻击。 你的团队已经通过备份从攻击中恢复。 你的工作是进行事后分析，并确定哪些行为者参与其中以及你的系统上发生了什么。 你已收到团队提供的原始内存转储以开始分析。

内存文件位于 `~/Desktop/Investigations/Investigation-2.raw`。

:::info 回答以下问题

<details>

<summary> PID 740 正在运行什么可疑进程？ </summary>

```plaintext
@WanaDecryptor@
```

</details>

<details>

<summary> PID 740 中可疑二进制文件的完整路径是什么？ </summary>

```plaintext
C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
```

</details>

<details>

<summary> PID 740 的父进程是什么？ </summary>

```plaintext
tasksche.exe
```

</details>

<details>

<summary> 根据我们当前的信息，系统上存在什么恶意软件？ </summary>

```plaintext
Wannacry
```

</details>

<details>

<summary> 可以使用什么插件来识别从恶意软件工作目录加载的所有文件？ </summary>

```plaintext
windows.filescan
```

</details>

:::

## 任务8结论

我们只涵盖了使用 Volatility 进行内存取证的一个非常浅的层面，在分析 Windows、Mac 和 Linux 架构时，它可以深入得多。 如果你想深入了解内存取证，我建议阅读 **《内存取证的艺术》**。

此外，以下是一些值得提及的插件列表，你可以了解并进一步阅读：

- `windows.callbacks`：恶意软件可能会为进程创建、映像加载或线程创建注册恶意回调。 我们可以使用此插件来检查未知驱动程序关联或非标准模块的回调函数。
- `windows.driverirp`：此插件检查驱动程序的 IRP（I/O 请求包）调度表。 可疑驱动程序可能不注册任何 IRP 函数或指向非驱动程序内存。
- `windows.modscan`：此插件扫描已加载的内核模块，而不依赖链表。 它可用于发现逃避`modules`和`driverscan`的隐形驱动程序。
- `windows.moddump`：此插件允许分析人员从内存中提取可疑驱动程序或模块进行静态分析。 可以使用Ghidra或IDA等工具进一步调查，对转储的模块进行逆向工程。
- `windows.memmap`：此插件可以对注入代码或内存工件进行更深入的分析，从特定进程中提取内存区域。
- `yarascan`：此插件将使用YARA文件作为参数或在命令行中列出规则，根据规则集搜索字符串、模式和复合规则。

在下一个房间[内存获取](https://tryhackme.com/room/memoryacquisition)中，我们将详细介绍内存获取，涵盖所有必要的技术和方法。

:::info 回答以下问题

<details>

<summary> 阅读以上内容并继续学习！ </summary>

```plaintext
No answer needed
```

</details>

:::
