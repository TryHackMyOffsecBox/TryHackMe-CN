---
sidebar_position: 3
---

# Windows内存与进程

## 任务 1 介绍

了解如何分析内存是取证分析师的一项基本技能。 攻击者通常完全在内存中运行其恶意软件，而不在存储设备上留下任何痕迹。 分析内存比分析存储设备稍复杂一些，需要结构化的方法。 幸运的是，像Volatility和Redline这样的工具可以帮助从内存中提取信息。 这些工具并不能自动化整个内存分析过程。 仍然需要取证分析师提取正确的信息并将其关联起来。

本房间是三个房间系列中的第一个。 它将指导您分析Windows主机的完整内存转储，并从中提取进程信息。 如果主机确实被入侵，您需要拼凑出攻击的范围和攻击链。

### 学习目标

- 使用Volatility从内存转储中提取进程和进程信息
- 分析提取的信息
- 报告发现结果

### 房间先决条件

- [Volatility](https://tryhackme.com/room/volatility)
- [Windows基础](https://tryhackme.com/module/windows-fundamentals)模块

:::info 回答以下问题

<details>

<summary>准备好开始分析您的第一个内存转储了吗？ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务2场景信息

### 场景

您是处理TryHatMe公司事件的事件响应团队的一员，该公司专门在线销售帽子。 您的任务是分析一个可能被入侵的Windows主机的完整内存转储。 在您之前，另一位分析师已经获取了完整的内存转储，并从TryHatMe的IT支持团队收集了所有必要信息。 由于这是您的第一个案例，您有点紧张，但别担心；一位资深分析师将指导您。

### 事件信息THM-0001

- 2025年5月5日07:30 CET，TryHatMe启动了其事件响应计划，并将事件上报给我们。 经过初步分类，我们的团队发现了一台可能被入侵的Windows主机。 主机的详细信息如下：
  - 主机名：WIN-001
  - 操作系统：Windows 1022H 10.0.19045
- 07:45 CET，我们的分析师Steve Stevenson获取了Windows主机的完整内存转储，并生成了哈希值以确保其完整性。 内存转储的详细信息如下：
  - 名称：`THM-WIN-001_071528_07052025.dmp`
  - MD5哈希：`78535fc49ab54fed57919255709ae650`

### 公司信息TryHatMe

#### 网络拓扑图

![TryHatMe公司的网络拓扑图](img/image_20251242-204239.png)

:::info 回答以下问题

<details>

<summary>我已阅读案例详情，准备好了解更多信息。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务3 Windows进程架构

您可能想知道从哪里开始分析内存转储。 让我们从Windows主机上进程的关键结构的高级概述开始。 这些结构对于理解像`volatility`这样的工具从哪里提取信息至关重要。

### Windows进程和线程

Windows使用四种结构来创建和管理进程：

- **EPROCESS**是**内核**中进程的表示
- **ETHREAD**是**内核**中线程的表示
- **进程环境块（PEB）**保存进程范围的配置和运行时数据，位于**用户空间**
- **线程环境块（TEB）**保存线程特定的配置和其他信息，包括线程本地存储（TLS）、异常处理数据以及关于堆栈的信息，位于**用户空间**

![Windows进程架构](img/image_20251244-204438.png)

#### 这些结构如何关联？

当Windows创建一个进程时，它会执行函数`CreateProcess()`。 此函数启动进程启动，包括以下步骤：

![Windows进程创建流程图](img/image_20251246-204639.png)

1. 内核创建一个EPROCESS和ETHREAD对象，并将它们链接在一起。 EPROCESS有一个名为`ThreadListHead`的字段，用于跟踪其所有线程
2. 虚拟内存被初始化：
   - 进程被分配一个虚拟地址空间（在用户模式下）
     映像（EXE）被映射到内存中
     为PEB和TEB分配空间
     创建进程参数
3. PEB和TEB被初始化。
   - EPROCESS包含一个指向PEB的指针
   - ETHREAD包含一个指向TEB的指针
   - TEB包含一个冗余的指向PEB的指针
4. 线程上下文被设置，但保持挂起状态。 此线程上下文包括：
   - 程序的起始地址
   - 堆栈指针
   - 指令指针
5. 进程已创建，但仍处于挂起状态
6. 进程的主线程被恢复。 这是进程的实际开始

### 您可以从这些结构中提取哪些信息？

像`volatility`这样的工具理解进程的架构，可以从这些结构中提取并关联数据。 特定的`volatility`模块将针对这些结构的某些字段。 下面，您可以找到每个结构的有趣字段概述。 **注意：仅列出了每个结构的相关字段。 其他字段已被省略。**

#### EPROCESS

以下`volatility`插件从EPROCESS提取信息：`pslist`、`pstree`、`psscan`、`malfind`、`getsids`、`handles`、`dlllist`、`cmdline`、`envars`和`ldrmodules`。 在下面的终端中，您可以找到这些模块针对的字段：

```c title="EPROCESS STRUCTURE"
struct _EPROCESS { 
    HANDLE UniqueProcessId; // PID (Process ID) 
    LIST_ENTRY ActiveProcessLinks; // Link in active process list (Used to keep track of all active processes) 
    UCHAR ImageFileName[15]; // Short process name LARGE_INTEGER CreateTime; // Process creation time 
    LARGE_INTEGER ExitTime; // Exit time if terminated 
    PPEB Peb; // Pointer to user-mode PEB 
    HANDLE InheritedFromUniqueProcessId; // Parent PID 
    LIST_ENTRY ThreadListHead; // List of ETHREADs 
    PHANDLE_TABLE ObjectTable; // Handle table (points to opened files) 
    PVOID SectionObject; // Executable image mapping 
    PVOID VadRoot; // VAD tree for memory mapping PACCESS_TOKEN Token; // Security information 
}
```

#### ETHREAD

以下`volatility`插件从ETHREAD提取信息：`threads`、`ldrmodules`、`apihooks`和`malfind`。 在下面的终端中，您可以找到这些模块针对的字段：

```c title="THREAD STRUCTURE"
struct _ETHREAD { 
    CLIENT_ID Cid; // Thread and Process IDs 
    LARGE_INTEGER CreateTime; // Thread creation time 
    LARGE_INTEGER ExitTime; // Thread exit time 
    PVOID StartAddress; // Kernel-level entry point 
    PVOID Win32StartAddress; // User-mode entry point 
    LIST_ENTRY ThreadListEntry; // Link in EPROCESS's thread list 
    PTEB Teb; // Pointer to TEB 
    ULONG ThreadState; // Thread execution state 
    ULONG WaitReason; // Reason for being blocked 
}
```

#### PEB

以下`volatility`插件从进程环境块提取信息：`cmdline`、`envars`、`ldrmodules`和`malfind`。 在下面的终端中，您可以找到这些模块针对的字段：

```c title="PEB STRUCTURE"
struct _PEB { 
    BOOLEAN BeingDebugged; // Debug flag
    PVOID ImageBaseAddress; // Base address of executable 
    PPEB_LDR_DATA Ldr; // Loader data (DLLs) 
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;// Command-line, environment variables
    ULONG NtGlobalFlag; // Debugging heap flags 
    PVOID ProcessHeap; // Default process heap 
}
```

#### TEB

以下`volatility`插件从线程环境块提取信息：`threads`和`malfind`。 在下面的终端中，您可以找到这些模块针对的字段：

```c title="TEB STRUCTURE"
struct _TEB { 
    PVOID EnvironmentPointer; // Pointer to env block 
    CLIENT_ID ClientId; // Thread + Process IDs 
    PVOID ThreadLocalStoragePointer; // TLS base 
    PPEB ProcessEnvironmentBlock; // Pointer to PEB 
    ULONG LastErrorValue; // Last error value 
    PVOID StackBase; // Upper bound of thread stack 
    PVOID StackLimit; // Lower bound of thread stack 
    PVOID Win32ThreadInfo; // GUI subsystem data 
}
```

:::info 回答以下问题

<details>

<summary>哪个字段用于跟踪所有活动进程？ 仅输入字段名称。 </summary>

```plaintext
ActiveProcessLinks
```

</details>

<details>

<summary> 哪个字段用于存储进程的PID？ 仅输入字段名称。 </summary>

```plaintext
UniqueProcessId
```

</details>

:::

## 任务4 新内存转储的初步分析

你在上一个任务中复习了Windows内存和进程的知识。 你已经准备好应对分析所提供内存转储的有趣挑战了。 在此任务中，你将启动分析虚拟机并验证内存转储的哈希值。 然后，你将使用 `volatility` 继续提取内存转储中的进程。 之后，你将分析结果并寻找可疑进程。 最后，你将记录你的发现。

### 环境与设置

在你的调查过程中，你将使用一个安装了内存分析工具 `volatility` 版本3的Ubuntu Desktop主机。 我们已将完整命令（python3 vol.py）的别名设置为 `vol3` 来启动 `volatility`。 现在点击此任务顶部的 `启动机器` 按钮来启动虚拟机。 虚拟机将以分屏视图启动。 如果它没有显示出来，你可以按页面顶部的 `显示分屏视图` 按钮。

Ubuntu Desktop的默认安装附带了一些命令行工具，它们可以补充 `volatility` 并允许你更详细地解析分析结果。 这些工具包括 `strings`、`diff`、`grep`、`comm`、`awk` 等。

### 验证内存转储

在分析虚拟机上打开一个shell并导航到 `/home/ubuntu`。 然后使用 `md5sum` 命令计算内存转储的MD5哈希值。 **注意：你不需要输入此命令。 我们已经为你预先计算好了哈希值。 由于资源有限，计算MD5哈希值可能需要长达五分钟。**

```shell title="Calculate MD5 Hash"
ubuntu@tryhackme:~$ md5sum THM-WIN-001_071528_07052025.mem > newhash.txt
```

然后，将新计算的哈希值与从进行内存获取的同事那里收到的哈希值进行比较：

```shell title="Compare Hashes"
ubuntu@tryhackme:~$ diff acquisitionhash.txt newhash.txt
```

如果上述命令没有显示输出，则哈希值相同。 现在你已经验证了内存转储的完整性，可以继续提取其内容了。

### 提取进程

`volatility` 附带多个模块，可以帮助你提取进程及其信息：

- `windows.pslist`：提取**内存转储时处于活动状态的进程**列表
- `windows.psscan`：提取**所有进程对象**，包括已终止和已解除链接的进程
- `windows.pstree`：提取**内存转储时处于活动状态的进程**列表，并可视化它们之间的父子关系
- `windows.psxview`：使用多种进程检测技术来收集有关进程、线程、进程结构和句柄的信息，然后交叉引用和比较这些信息。

导航到虚拟机并打开一个终端。 现在，输入以下命令从内存转储中提取活动进程并将其保存到文本文件中。 **注意：由于内存转储的大小和资源有限，命令可能需要长达一分钟才能完成运行。**

```shell title="Extract Processes"
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.pslist > pslist.txt
```

现在，使用 `cat` 命令显示 `pslist.txt` 的内容并分析输出。 这里有一个提示：将输出通过管道传递给 `less` 命令以获得可滚动的输出。 然后你可以**按空格键滚动浏览输出**。 你可以按 `q` 键退出。

```shell title="Display Extracted Processes"
ubuntu@tryhackme:~$ cat pslist.txt | less
Volatility 3 Framework 2.26.2
PID PPID ImageFileName Offset(V) Threads Handles SessionId Wow64 CreateTime ExitTime File output
        
4   0   System         0x990b2366a040 138 - N/A False 2025-05-07 07:08:48.000000 UTC N/A Disabled
92  4   Registry       0x990b236dc080 4 - N/A False 2025-05-07 07:08:44.000000 UTC N/A Disabled
324 4   smss.exe       0x990b2680e040 2 - N/A False 2025-05-07 07:08:48.000000 UTC N/A Disabled
440 420 csrss.exe      0x990b26cf0140 12 - 0 False 2025-05-07 07:08:48.000000 UTC N/A Disabled
516 508 csrss.exe      0x990b274bd080 13 - 1 False 2025-05-07 07:08:48.000000 UTC N/A Disabled
524 420 wininit.exe    0x990b2758a140 1 - 0 False 2025-05-07 07:08:48.000000 UTC N/A Disabled
592 508 winlogon.exe   0x990b275c00c0 6 - 1 False 2025-05-07 07:08:48.000000 UTC N/A Disabled
        
[REDACTED FOR READABILITY]
```

### 大海捞针

你正在寻找与以下任一指标匹配的可疑进程：

#### 可疑名称

攻击者喜欢使用域名抢注来伪装成合法进程。 例如：

- `scvhost.exe` 而不是 `svchost.exe`
- `explorere.exe` 而不是 `explorer.exe`
- `lsasss.exe` 而不是 `lsass.exe`

#### 可疑路径

攻击者会使用与合法进程相同的进程名称，但这些进程位于不寻常的路径中。 例如：

- `svchost.exe` 从 `C:\Users\analyst\` 启动，而不是从 `C:\Windows\System32\`
- `cmd.exe` 从 `C:\TMP\` 启动，而不是从 `C:\Windows\System32\`

#### 伪装

攻击者会使用模仿进程和系统服务的进程名称。 例如：

- `dockerupdater.exe`
- `defenderAV.exe`
- `pdfupdateservice.exe`

### 与基线比较

有时很难区分合法进程和恶意进程。 幸运的是，上一段中的进程列表并不那么广泛，但如果是的话，你可以使用以下方法来缩小需要检查的进程数量：

- 确保你有一个在正常情况下主机上运行的进程基线。 例如，在正常工作时间
- 将 `windows.pslist` 输出与基线进行比较，以获得未包含在基线中的进程的候选列表
- 通过将进程与更新软件时运行的常见进程候选列表进行比较来过滤进程。 你可以检查任务计划程序来找到这些进程
- 调查剩余的进程

继续在虚拟机中操作，输入以下命令将 `pslist.txt` 文件与位于 `~\baseline\` 的 `baseline.txt` 文件进行比较（注意：基线文件是从任务管理器中提取的，因此你需要先准备它）：

```shell title="Comparing with Baseline"
ubuntu@tryhackme:~$ awk 'NR >3{print $2}' baseline/baseline.txt | sort | uniq > baseline_procs.txt
ubuntu@tryhackme:~$ awk 'NR >3{print $3}' pslist.txt | sort | uniq > current_procs.txt
ubuntu@tryhackme:~$ comm -13 baseline_procs.txt current_procs.txt
[REDACTED FOR READABILITY]
WINWORD.EXE
ai.exe
audiodg.exe
cmd.exe
fontdrvhost.ex
msdtc.exe
pdfupdater.exe
smartscreen.ex
sppsvc.exe
updater.exe
userinit.exe
vm3dservice.ex
vmtoolsd.exe
windows-update
```

上面终端中包括 `awk` 的前两行准备要比较的文件：

- `awk 'NR >3{print $2}'` 将文件内容按列划分，排除前3行，然后打印第n列作为输出
- `sort` 对从 `awk` 命令传递过来的值进行排序
- `uniq > *.txt` 过滤掉重复项，然后将数据保存到文本文件

`comm` 命令比较每个准备好的文件的内容并输出差异。 设置了标志 `-13`，以便只显示 `current_procs.txt` 中独有的进程。

上面终端中列出的结果需要先进行解释。 其中包含的一些进程是误报。 例如，这些是：

- 在捕获基线时未运行的合法进程
- `ImageFileName` 字段过长并被截断的进程。 此字段最多只能容纳16个字节。

知道哪些进程是误报需要进行一些额外的研究。 以下进程已进入你的候选列表：

- `pdfupdater.exe`
- `windows-update.exe`
- `updater.exe`

### 分析笔记和后续步骤

你已经找到了三个需要进一步分析的可疑进程。 下表概述了这些可疑进程。

| ImageFileName                      | PID   | 时间戳                                                                        |
| :--------------------------------- | :---- | :------------------------------------------------------------------------- |
| pdfupdater.exe     | 3392  | 2025-05-07 07:13:05.000000 |
| windows-update.exe | 10084 | 2025-05-07 07:13:05.000000 |
| updater.exe        | 10032 | 2025-05-07 07:13:56.000000 |

继续下一个任务，看看这些进程是否相互关联或与其他进程关联。 这可能帮助您发现其他最初不可疑但在新上下文中变得可疑的进程。

:::info 回答以下问题

<details>

<summary> 拥有12个线程的csrss.exe进程的PID是什么？ 您可以使用`pslist.txt`文件来找到答案。 </summary>

```plaintext
440
```

</details>

<details>

<summary> PID为5672的进程的（内存）偏移量(V)是什么？ 您可以使用`pslist.txt`文件来找到答案。 </summary>

```plaintext
0x990b29293080
```

</details>

:::

## 任务5 关联进程

在之前的任务中，您发现了多个独立的可疑进程。 在深入挖掘这些进程的内存之前，您应该首先揭示这些进程与其他进程之间是否存在任何关联。 这将帮助您找到其他潜在的可疑进程。 下面的终端显示了恶意进程树可能的样子：

```shell
explorer.exe (PID: 1500)
└── cmd.exe (PID: 2200)                  ← Triggered by malicious LNK file
    └── powershell.exe (PID: 2210)       ← Downloads and executes the payload
        └── svchost.exe (PID: 2220)      ← Masquerades as a system process
            └── asyncrat.exe (PID: 2230) ← Remote Access Trojan (C2 beaconing)
```

上面的示例是一个攻击链，其中asyncrat（一种常见的远程访问木马）在用户点击恶意LNK文件后被部署。 LNK文件生成一个命令行`cmd.exe`，然后启动PowerShell以下载并执行有效负载。 PowerShell反过来使用svchost.exe伪装成系统进程并生成`asyncrat.exe`。

继续使用虚拟机，输入以下命令以生成显示内存转储进程父子关系的树结构。 **注意：由于内存转储的大小和资源有限，命令可能需要长达一分钟才能完成运行。**

```shell title="Show Process Tree"
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.pstree > processtree.txt
```

使用`cat`命令显示的输出相当庞大。 您可以使用`cut`命令处理`processtree.txt`文件，仅显示PID、PPID和映像名称值。 输入以下命令来完成此操作：

```shell title="Parse Process Tree"
ubuntu@tryhackme:~$ cut -d$'\t' -f1,2,3 processtree.txt
PID             PPID    ImageFileName
[REDACTED]
592             508     winlogon.exe
* 5232          592     userinit.exe
** 5672         5232    explorer.exe
*** 5952        5672    cmd.exe
**** 3144       5952    conhost.exe
*** 5252        5672    WINWORD.EXE
**** 3392       5252    pdfupdater.exe
***** 2576      3392    conhost.exe
***** 10084     3392    windows-update
****** 10032    10084   updater.exe
******* 432     10032   cmd.exe
******** 4592   432     conhost.exe
******** 6984   432     powershell.exe
**** 3932       5252    ai.exe
*** 8936        5672    SecurityHealth
*** 9096        5672    msedge.exe
**** 8100       9096    msedge.exe
**** 9164       9096    msedge.exe
**** 3500       9096    msedge.exe
**** 7408       9096    msedge.exe
**** 9264       9096    msedge.exe
**** 4152       9096    msedge.exe
**** 7420       9096    msedge.exe
[REDACTED]
```

为便于阅读，上述结果已进行编辑。 显示的结果包括您在之前任务中发现的相关进程。

### 观察结果

现在定位您在任务3期间注意到的进程，并检查它们是否与其他进程相关。 从WINWORD.exe进程开始，您可以看到清晰的树结构。 我们将树转换为ASCII树结构以更清晰地显示。

```shell
PID         PPID    IMAGENAME
5252        5672    WINWORD.EXE
└── 3392       5252    pdfupdater.exe    
    ├── 2576      3392    conhost.exe    
    └── 10084     3392    windows-update        
        └── 10032    10084   updater.exe            
            └── 432     10032   cmd.exe                
                ├── 4592   432     conhost.exe                
                └── 6984   432     powershell.exe
```

现在从底部开始记录观察结果：

- 进程`powershell.exe`，其PID为... 其PPID为...
- 进程`conhost.exe`，其PID为... 其PPID为...
- 与PPID ...关联的进程 是`cmd.exe`，其PID为...
- 依此类推

### 分析笔记和后续步骤

| ImageFileName                      | PID   | PPID  | 时间戳                                                                        |
| :--------------------------------- | :---- | :---- | :------------------------------------------------------------------------- |
| WINWORD.EXE        | 5252  | 5672  | 2025-05-07 07:13:04.000000 |
| pdfupdater.exe     | 3392  | 5252  | 2025-05-07 07:13:05.000000 |
| conhost.exe        | 2576  | 3392  | 2025-05-07 07:13:05.000000 |
| windows-update.exe | 10084 | 3392  | 2025-05-07 07:13:05.000000 |
| updater.exe        | 10032 | 10084 | 2025-05-07 07:13:56.000000 |
| cmd.exe            | 432   | 10032 | 2025-05-07 07:14:36.000000 |
| conhost.exe        | 4592  | 432   | 2025-05-07 07:14:36.000000 |
| powershell.exe     | 6984  | 432   | 2025-05-07 07:14:39.000000 |

从观察结果（见上表）中，我们可以得出结论：`updater.exe`进程是`windows-update.exe`的子进程，而`windows-update.exe`是`pdfupdater.exe`的子进程。 `pdfupdater.exe`进程是`WINWORD.exe`的子进程。 这个进程链看起来相当可疑：

- 其中多个进程的名称中包含`update`
- `WINDWORD.exe`进程启动了`pdfupdater.exe`进程。 这意味着Microsoft Word正在更新一个与PDF相关的工具
- 然后`pdfupdater.exe`进程启动了`windows-update.exe`。 一个更新某个软件的工具不太可能同时启动`windows-update.exe`进程来更新Windows操作系统
- 最重要的是，`windows-update.exe`进程启动了`updater.exe`进程，这似乎暗示了又一次更新
- `conhost.exe`进程的存在也表明这些进程似乎启动了网络连接

仔细观察这些观察结果和备注，并将其与事实信息（如Windows、PDF工具和Microsoft Word更新过程的工作原理及其合法进程名称）进行比较，您可以得出结论：这个进程链极有可能是恶意的。

既然您已经发现了一个潜在的恶意链，您必须深入挖掘。 继续下一个任务，以发现已终止和隐藏的进程，并分析本任务中发现的可疑进程。

:::info 回答以下问题

<details>

<summary> services.exe（PID 664）进程的父ID（PPID）是什么？ 使用processtree.txt文件来回答问题。 </summary>

```plaintext
524
```

</details>

<details>

<summary> 拥有PID 7788的进程的映像文件名是什么？ 使用processtree.txt文件来回答问题。 </summary>

```plaintext
FTK Imager.exe
```

</details>

:::

## 任务6 深入挖掘

到目前为止，您一直专注于发现和关联属于活动内存的进程。 `volatility`还可以扫描最近被终止、取消链接或被攻击者隐藏的进程。 攻击者经常采用不同的技术来隐藏进程、线程、驱动程序和注册表项。 您可以使用`volatitlity`模块`windows.psscan`和`windows.psxview`来获取所有进程结构的概览，包括那些不在活动进程链接结构中的进程。

### PSSCAN

继续使用虚拟机，输入下面显示的命令以扫描不属于活动进程列表的进程。 **注意：由于内存转储的大小和资源有限，命令完成运行可能需要长达三分钟。**

```shell title="PSSCAN"
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.psscan > psscan.txt
```

您可以将`psscan`的结果与`pslist`的结果进行比较，以发现隐藏的进程。 在比较之前，您首先需要准备输出文件。 输入以下命令以从`psscan.txt`和`pslist.txt`文件中提取PID和进程名称，并将输出保存到新文件。

```shell title="Prepare Files"
ubuntu@tryhackme:~$ awk '{print $1,$3}' pslist.txt | sort > pslist_processed.txt
ubuntu@tryhackme:~$ awk '{print $1,$3}' psscan.txt | sort > psscan_processed.txt
```

然后，您可以比较两个文件以发现隐藏的进程：

```shell title="Prepare Files"
ubuntu@tryhackme:~$ comm -23 psscan_processed.txt pslist_processed.txt
5548 sihost.exe
5592 svchost.exe
5736 svchost.exe
5748 svchost.exe
5752 taskhostw.exe
5828 svchost.exe
5908 svchost.exe
5972 ctfmon.exe
8708 svchost.exe
9040 vmtoolsd.exe
```

此比较的结果是良性的。 所有列出的进程都是在Windows主机上运行的常见进程。 例如，`svchost.exe` 是一个托管和运行 Windows 服务的常见进程。 您可以进行一些检查来验证 `svchost.exe` 确实是良性的：

- 检查映像路径：如果它不在 `C:\Windows\System32\` 中，则很可疑
- 检查为此进程加载的 DLL：攻击者可以使用进程空洞化或 DLL 注入等技术来破坏合法进程
- 检查进程是否仍有活动线程：如果它有活动线程但未出现在 `pslist` 结果中，则很可疑。 可能是攻击者隐藏了该进程
- 如果活动进程没有任何线程，则被视为可疑。 每个活动进程应至少拥有 1 个线程。 攻击者可以使用技术来改变线程
- 检查 `Exit Time`：如果进程确实已终止，它应显示一个 `Exit Time`。 如果仍有与该进程关联的活动或孤立线程，则很可疑。
- 转储进程内存并进一步分析

您稍后将探索其中一些检查。
PSXVIEW

现在，运行 windows.psxview 模块。 windows.psxview 是一种在一次操作中进行多项测试并交叉引用结果的好方法。 您应查找未在 pslist 结果中列出但在其他测试中列出的进程。 输入以下命令以运行 windows.psxview 模块。 注意：由于内存转储的大小和资源有限，命令完成运行可能需要长达三分钟。

### PSXVIEW

现在，运行 `windows.psxview` 模块。 `windows.psxview` 是一种在一次操作中进行多项测试并交叉引用结果的好方法。 您应查找未在 `pslist` 结果中列出但在其他测试中列出的进程。 输入以下命令以运行 `windows.psxview` 模块。 **注意：由于内存转储的大小和资源有限，命令完成运行可能需要长达三分钟。**

```shell title="PSXVIEW"
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.psxview > psxview.txt
```

然后，您可以使用 `awk` 过滤结果并显示 `pslist` 测试等于 false 的所有行，如下所示：

```shell title="Filter Results"
ubuntu@tryhackme:~$ awk 'NR==3 || $4 == "False"' psxview.txt
Offset(Virtual) Name            PID     pslist  psscan  thrdscan  csrss   Exit Time
0xac80001ca080  svchost.exe     5828    False   True    False     False
0xac8000083080  svchost.exe     5592    False   True    False     False
0xac80000b90c0  vmtoolsd.exe    9040    False   True    False     False
0xac8000084080  svchost.exe     5748    False   True    False     False
0xac80001c6080  svchost.exe     5908    False   True    False     False
0xac80001d2080  ctfmon.exe      5972    False   True    False     False
0xac8000030080  svchost.exe     5736    False   True    False     False
0xac80000a1080  sihost.exe      5548    False   True    False     False
0x990b29bef080  svchost.exe     8708    False   True    False     False   2025-05-07 07:13:16+00:00
0xac8000031080  taskhostw.exe   5752    False   True    False     False
```

上面终端中的输出没有显示任何可能暗示攻击者隐藏恶意进程的明显内容。 然而，您永远无法 100% 确定。 如果您仍然对列出的进程感到怀疑，请应用 **psscan 部分** 中列出的相同检查。

### 分析笔记和后续步骤

您未使用 volatility 模块 `psscan` 和 `psxview` 发现新进程。

在下一个任务中，您将专注于分析先前任务中发现的进程。

:::info 回答以下问题

<details>

<summary> 拥有 0 个线程的进程数量是多少？ 使用 `psscan.txt` 文件回答问题。 </summary>

```plaintext
3
```

</details>

<details>

<summary> 填写了退出时间的进程数量是多少？ 使用 `psxview.txt` 文件回答问题。 </summary>

```plaintext
3
```

</details>

:::

## 任务 7 转储进程内存

在之前的任务中，您发现了一个潜在的恶意进程链。 根据收集到的信息，您只能得出结论：这些进程是相互关联的，并且该链从 `WINWORD.exe` 进程开始。 您现在应专注于通过转储其内存从进程中提取信息。

`volatility` 包含多个模块来协助您完成此操作。 模块 `windows.dlllist` 和 `windows.dumpfiles` 应帮助您发现多个入侵指标。

### 查找路径

使用 `windows.dlllist` 模块，您可以发现主可执行文件及其链接的 DLL 的路径。 继续使用虚拟机，在您在任务 5 中记录的进程上运行模块 `windows.dlllist`（`WINWORD.exe`、`pdfupdater.exe`、`updater.exe`、`windows-update`、`cmd.exe`、`conhost.exe`、`powershell.exe`）。 输入以下命令以转储 `WINWORD.exe` 进程。 **注意：由于内存转储的大小和资源有限，命令完成运行可能需要长达两分钟。**

```shell title="Check Results"
ubuntu@tryhackme:~$ vol3 -f THM-WIN-001_071528_07052025.mem windows.dlllist --pid 5252 > 5252_dlllist.txt
```

**现在，对所有其他进程执行相同操作。** 然后，使用 `cat` 检查每个文件，查找主可执行文件的路径，并将其记录下来。

```shell title="Check Results"
ubuntu@tryhackme:~$ cat 5252_dlllist.txt
Volatility 3 Framework 2.26.2
Progress:  100.00               PDB scanning finished
PID   Process Base  Size      Name                  Path                                                               LoadTime                File output
5252  WINWORD.EXE   0x670000  0x1ac000 WINWORD.EXE  C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE  2025-05-07 07:13:04.00
        
[REDACTED FOR READABILITY]
```

现在，用新发现更新您已有的信息。

`pdfupdater.exe`、`windows-update.exe` 和 `updater.exe` 进程似乎从异常位置启动。 当您专注于调查用户活动时，此信息将很有帮助。

### 转储进程内存

到目前为止，您已发现多个可疑进程。 这种怀疑基于进程名称、具有多个更新进程的进程树以及从用户路径启动的进程。

您必须转储并分析进程的内存，以确认这些进程是恶意的。 然后，您可以提取可执行文件并运行 strings 命令，以快速查看是否存在任何恶意指标。 在大多数情况下，您会将可执行文件传递给恶意软件分析师进行进一步调查。 以下是转储 PID 为 5252 的进程的命令。 按照相同的步骤转储其他进程的内存；您可以排除 cmd.exe、PowerShell.exe 和 conhost.exe 进程。 其他 `volatility` 模块可以更好地分析这些进程。 **注意：由于内存转储的大小和资源有限，命令完成运行可能需要长达一分钟。**

```shell title="Dump Process Memory"
ubuntu@tryhackme:~$ mkdir 5252
ubuntu@tryhackme:~$ cd 5252
ubuntu@tryhackme:~/5252$ vol3 -f ../THM-WIN-001_071528_07052025.mem windows.dumpfiles --pid 5252
```

转储的文件都遵循相同的命名约定：`file.StartAddress.EndAddress.ImageSectionObject.filename.img` 或 `file.StartAddress.EndAddress.DataSectionObject.filename.dat`。

注意 ImageSectionObject 和 DataSectionObject 之间的区别。

| 特性   | ImageSectionObject      | DataSectionObject |
| :--- | :---------------------- | :---------------- |
| 目的   | 映射的可执行映像                | 映射的数据             |
| 典型内容 | `.exe`、`.dll`、注入的 PE 文件 | 配置、日志、解压的有效载荷     |
| 可执行？ | 是                       | 通常否               |

### 查找内容

根据进程的不同，从进程转储的文件数量可能很大。 您应根据进程的上下文过滤特定扩展名。 例如：

- 如果您转储 Microsoft Word 进程，搜索具有扩展名 `.docm`、`.dotm` 或 `.dotx` 的启用宏的文件会很有趣。 攻击者经常使用此类文件来执行 Visual Basic 代码并下载攻击的下一阶段。 MITRE 将此归类为 [T1059.005 – 命令和脚本解释器：Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- 如果您有一个名称可疑的进程，请查找 `.exe` 和 `.dat` 文件。 使用 strings 命令快速检查任何恶意指标，如可疑函数名、URL、IP、系统命令等
- 如果您转储 PDF 阅读器进程，请查找 .pdf 文件。 使用 strings 命令快速检查任何恶意指标，如包含的 JavaScript。 MITRE将此归类为[T1059.007 – 命令和脚本解释器：JavaScript](https://attack.mitre.org/techniques/T1059/007/)

进程5252是Windows Word进程。 查找`.docm`或`.dotm`文件并记录您的发现。 注意：所有转储的文件都附加了扩展名`.img`。 您可以使用file命令验证文件的类型。

```shell title="Find Macro Files"
ubuntu@tryhackme:~$ ls 5252 | grep -E ".docm|.dotm" -i
file.0x990b2ae077d0.0x990b2a3f5d70.SharedCacheMap.Normal.dotm.vacb
file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
file.0x990b2ae0ab60.0x990b28043a00.SharedCacheMap.cv-resume-test.docm.vacb
file.0x990b2ae0ab60.0x990b2a8b4b30.DataSectionObject.cv-resume-test.docm.dat
                
ubuntu@tryhackme:~$ file 5252/file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat      
5252/file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat: Microsoft Word 2007+
```

继续处理其他进程，重点查找`.exe`和`.dat`文件。 您可以跳过进程`cmd.exe`、`conhost.exe`和`PowerShell.exe`。 这些进程将在后续房间中进行分析。 您可以使用以下`grep`命令来筛选`.exe`和`.dat`文件。

```shell title="Find Executables"
ubuntu@tryhackme:~$ ls 3392 10084 10032 | grep -E ".exe|.dat" -i
file.0x990b2ae26720.0x990b286fa140.ImageSectionObject.updater.exe.img
file.0x990b2846e310.0x990b282f5b70.DataSectionObject.cversions.2.db.dat
file.0x990b2ae16230.0x990b29ad0270.ImageSectionObject.windows-update.exe.img
file.0x990b2ae16230.0x990b2b92ce90.DataSectionObject.windows-update.exe.dat
file.0x990b2ae0ee90.0x990b2a466010.ImageSectionObject.pdfupdater.exe.img
file.0x990b2ae0ee90.0x990b2b91f290.DataSectionObject.pdfupdater.exe.dat
```

记录您找到的所有文件并更新您的发现。

### 分析笔记和后续步骤

您已更详细地分析了可疑进程，并发现了多个情况：

- `updater.exe`、`pdfupdater.exe`和`windows-update.exe`的路径可疑。 它们都从用户文件夹启动
- `WINWORD.EXE`进程转储包含两个启用宏的Word文件，名为`cv-resume-test.docm`和`normal.dotm`。 这些可能是恶意文件，需要进一步分析

您还提取了`updater.exe`、`pdfupdater.exe`和`windows-update.exe`进程的可执行文件。 恶意软件分析师需要进一步分析这些可执行文件。
下表列出了发现结果。

| PID   | PID   | 时间戳                                                                        | 路径                                                                                                                                | 文件 - 可执行文件                                                                                                                                                                                                                                                                                                                                                    |
| :---- | :---- | :------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 5252  | 5672  | 2025-05-07 07:13:04.000000 | C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE              | file.0x990b2ae0ab60.0x990b2a8b4b30.DataSectionObject.cv-resume-test.docm.dat<br />file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat        |
| 3392  | 5252  | 2025-05-07 07:13:05.000000 | C:\Users\operator\pdfupdater.exe                                                                  | file.0x990b2ae0ee90.0x990b2a466010.ImageSectionObject.pdfupdater.exe.img<br />file.0x990b2ae0ee90.0x990b2b91f290.DataSectionObject.pdfupdater.exe.dat         |
| 2576  | 3392  | 2025-05-07 07:13:05.000000 | ??\C:\Windows\system32\conhost.exe                                                                | /                                                                                                                                                                                                                                                                                                                                                             |
| 10084 | 3392  | 2025-05-07 07:13:05.000000 | C:\Users\operator\AppData\Roaming\Microsoft\Windows\StartMenu\Programs\Startup\windows-update.exe | file.0x990b2ae16230.0x990b29ad0270.ImageSectionObject.windows-update.exe.img<br />file.0x990b2ae16230.0x990b2b92ce90.DataSectionObject.windows-update.exe.dat |
| 10032 | 10084 | 2025-05-07 07:13:56.000000 | "C:\Users\operator\Downloads\updater.exe"                                                         | file.0x990b2ae26720.0x990b286fa140.ImageSectionObject.updater.exe.img                                                                                                                                                                                         |
| 432   | 10032 | 2025-05-07 07:14:36.000000 | C:\Windows\system32\cmd.exe                                                                       | /                                                                                                                                                                                                                                                                                                                                                             |
| 4592  | 432   | 2025-05-07 07:14:36.000000 | ??\C:\Windows\system32\conhost.exe                                                                | /                                                                                                                                                                                                                                                                                                                                                             |
| 6984  | 432   | 2025-05-07 07:14:39.000000 | powershell                                                                                                                        | /                                                                                                                                                                                                                                                                                                                                                             |

既然您已发现多个指向攻击的指标，您需要将提取的工件交给恶意软件分析师和/或威胁猎手进行进一步检查。

:::info 回答以下问题

<details>

<summary> PID为7788的进程路径是什么？ </summary>

```plaintext
C:\Program Files\AccessData\FTK Imager\FTK Imager.exe
```

</details>

<details>

<summary> 转储PID为7788的进程。 表示可执行文件的转储文件名称是什么？ </summary>

```plaintext
file.0x990b2ae1ed40.0x990b29954a20.ImageSectionObject.FTK Imager.exe.img
```

</details>

:::

## 任务8 整合所有信息

在分析内存转储时，您发现了可能的入侵指标。 不过，其中一些指标需要进一步分析才能确定。 根据收集的工件和观察结果，可以重建部分杀伤链。 下表显示了所有收集到的信息。

| PID   | PID   | 时间戳                                                                        | 路径                                                                                                                                 | 文件 - 可执行文件                                                                                                                                                                                                                                                                                                                                                    |
| :---- | :---- | :------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 5252  | 5672  | 2025-05-07 07:13:04.000000 | C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE               | file.0x990b2ae0ab60.0x990b2a8b4b30.DataSectionObject.cv-resume-test.docm.dat<br />file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat        |
| 3392  | 5252  | 2025-05-07 07:13:05.000000 | C:\Users\operator\pdfupdater.exe                                                                   | file.0x990b2ae0ee90.0x990b2a466010.ImageSectionObject.pdfupdater.exe.img<br />file.0x990b2ae0ee90.0x990b2b91f290.DataSectionObject.pdfupdater.exe.dat         |
| 2576  | 3392  | 2025-05-07 07:13:05.000000 | ??\C:\Windows\system32\conhost.exe                                                                 | /                                                                                                                                                                                                                                                                                                                                                             |
| 10084 | 3392  | 2025-05-07 07:13:05.000000 | C:\Users\operator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windows-update.exe | file.0x990b2ae16230.0x990b29ad0270.ImageSectionObject.windows-update.exe.img<br />file.0x990b2ae16230.0x990b2b92ce90.DataSectionObject.windows-update.exe.dat |
| 10032 | 10084 | 2025-05-07 07:13:56.000000 | C:\Users\operator\Downloads\updater.exe                                                            | file.0x990b2ae26720.0x990b286fa140.ImageSectionObject.updater.exe.img                                                                                                                                                                                         |
| 432   | 10032 | 2025-05-07 07:14:36.000000 | C:\Windows\system32\cmd.exe                                                                        | /                                                                                                                                                                                                                                                                                                                                                             |
| 4592  | 432   | 2025-05-07 07:14:36.000000 | ??\C:\Windows\system32\conhost.exe                                                                 | /                                                                                                                                                                                                                                                                                                                                                             |
| 6984  | 432   | 2025-05-07 07:14:39.000000 | powershell                                                                                                                         | /                                                                                                                                                                                                                                                                                                                                                             |

![基于收集信息的攻击链](img/image_20251234-213428.png)

### 初始访问

现在，您只能推测攻击者进入系统的技术。 根据您收集的工件，攻击者很可能采用了[T1566 钓鱼](https://attack.mitre.org/techniques/T1566/)技术，将恶意启用宏的Word文档放入系统。 这需要通过分析用户在系统上的活动来确认。

### 执行

第一个入侵指标始于`WINWORD.exe`进程打开一个名为`cv-resume-test.docm`或`normal.dotm`的启用宏的Word文件。 MITRE将此技术归类为[T1059.005 命令和脚本解释器：Visual Basic](https://attack.mitre.org/techniques/T1059/005/)

`cv-resume-text.docm`或`normal.dotm`文件很可能下载并启动名为`pdfupdater.exe`的第二阶段恶意软件。 对宏文件的进一步分析应能证实这一点。

### 持久性

恶意软件pdfupdater.exe随后很可能下载另一个阶段`windows-update.exe`，该文件从`C:\Users\operator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windows-update.exe`路径启动。 此路径通常包含操作系统加载时启动的进程或进程链接。 这可能是一个持久性指标。 MITRE将此归类为[启动或登录初始化脚本：启动项](https://attack.mitre.org/techniques/T1037/005)。

### 命令与控制

观察到`windows-update.exe`可执行文件很可能具有持久性，这可能表明它充当C2客户端或反向shell。 对此可执行文件的进一步分析应能揭示其功能。

### 未涵盖的攻击阶段

您已经发现了杀伤链中的多个阶段，但仍有一个可执行文件无法归入上述任何阶段。 目前，您只能推测updater.exe进程的作用。 一个合理的猜测是，由于它源自可能的C2进程`windows-update.exe`，它很可能包含MITRE战术，如[数据窃取](https://attack.mitre.org/tactics/TA0010)、[影响](https://attack.mitre.org/tactics/TA0040)、[发现](https://attack.mitre.org/tactics/TA0007)或[横向移动](https://attack.mitre.org/tactics/TA0008)。 对可执行文件的分析应能更清晰地揭示其功能。

### 后续步骤

您已发现多个需要进一步分析的工件。 您应收集这些工件，计算其哈希值，然后将其交给威胁猎手或恶意软件分析师。

:::info 回答以下问题

<details>

<summary> 可能被入侵的用户名称是什么？ </summary>

```plaintext
operator
```

</details>

<details>

<summary> MITRE战术命令与控制的ID是什么？ </summary>

```plaintext
TA0011
```

</details>

:::

## 任务9 结论

本房间是深入分析内存转储系列三个房间中的第一个。 您经历了一个真实场景，并分析了内存转储，重点是提取进程及其信息。 您发现了一个潜在的攻击链和多个可疑工件。

分析进程仅仅是开始。 接下来的步骤是分析用户和网络活动。

:::info 回答以下问题

<details>

<summary> 我已准备好应用新获得的技能！ </summary>

```plaintext
No answer needed
```

</details>

:::
