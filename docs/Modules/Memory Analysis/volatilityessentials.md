---
sidebar_position: 2
---

# Volatility Essentials

## Task 1 Introduction

In the previous room, [Memory Analysis Introduction](https://tryhackme.com/room/memoryanalysisintroduction), we learnt about the vital nature of memory forensics in cyber security. We explored the structure of memory dumps, differentiated between RAM and disk forensics, and saw scenarios where memory analysis is essential.

Here, we shall begin looking at the practical aspects of memory forensics through tools, specifically Volatility.

### Learning Objectives

- Getting familiar with the Volatility Framework
- Navigate and utilise basic Volatility commands and plugins
- Conduct forensic analysis to identify key artefacts such as running processes and loaded DLLs using Volatility

### Prerequisites

- [Memory Analysis Introduction](https://tryhackme.com/room/memoryanalysisintroduction)
- [Core Windows Processes](https://tryhackme.com/room/btwindowsinternals)

:::info Answer the questions below

<details>

<summary> Ready to learn about Volatility and memory analysis. </summary>

```plaintext
No answer needed
```

</details>

:::

## Task 2 Volatility Overview

[Volatility](https://volatilityfoundation.org/the-volatility-framework/) is an open-source memory forensics framework that is cross-platform, modular, and extensible. The framework has undergone various iterations over the years, with the current version being Volatility 3. This version is superior to its predecessors as it abandoned static OS profiling in favour of dynamic symbol resolution, supporting newer operating systems, memory layouts, and complete insight into the runtime state of the system.

### Architectural Overview

Volatility 3 is made up of several key layers:

- **Memory layers**: These layers represent the hierarchy of address spaces, from raw memory to virtual address translations.
- **Symbol tables**: The tables enable kernel and process structures to be interpreted through OS-specific debugging symbols.
- **Plugins**: These are modular routines that leverage the underlying memory layers and symbol tables to extract artefacts of forensic interest. Later in the room, we shall look at some key plugins used.

### System Requirements and Installation

Volatility 3 requires Python 3.6 or later to run. Additionally, it benefits from various libraries such as `pefile`, `capstone`, and `yara-python` that allow us to process portable executables, perform memory disassembly, and use YARA rules in our analysis, respectively. The terminal output below shows how to install Volatility by cloning the [GitHub repository](https://github.com/volatilityfoundation/volatility3.git) and running it directly from the source.

Volatility has already been installed on the machine attached to this room and can be accessed under the `Desktop/volatility3` directory.

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

:::info Answer the questions below

<details>

<summary> Read the above and navigate to the Volatility directory. </summary>

```plaintext
No answer needed
```

</details>

:::

## Task 3 Memory Acquisition and Analysis

### Memory Acquisition Methodologies

Memory acquisition is a foundational step in forensics that must be performed in a manner that ensures we maintain the integrity of evidence. The process and the deployment environment used vary from one OS to another.

For Windows systems, the following tools can be used to conduct memory acquisition:

- **DumpIt**: captures a full physical memory image on 32/64‑bit Windows and automatically hashes the output.
- **WinPmem**: Open‑source driver‑based tool that acquires RAM in RAW/ELF formats and embeds acquisition metadata for chain‑of‑custody.
- **Magnet RAM Capture**: GUI‑driven collector that snapshots volatile memory on live Windows hosts while minimising footprint.
- **FTK Imager**: The most common commercial tool that acquires memory and selected logical artefacts alongside disk imaging functions.

For Linux and macOS systems, we can employ the services of the following tools:

- **AVML**: Lightweight Microsoft CLI utility that dumps Linux memory to a compressed ELF file without requiring a kernel module.
- **LiME**: Loadable Kernel Module for Linux that captures full volatile memory over disk or network and supports ARM/x86 architectures.
- **OSXPmem**: macOS‑specific fork of Pmem that creates raw memory images on Intel‑based Macs for subsequent Volatility analysis.

Extracting memory from virtual environments can be done by collecting the virtual memory file from the host machine's drive. Depending on the hypervisor in use, the output file will likely differ, and you would likely encounter the following examples:

- VMware - `.vmem`
- Hyper-V - `.bin`
- Parallels - `.mem`
- VirtualBox - `.sav` It is worth noting that this is a partial memory file.

### Memory Analysis

To have a holistic and hands-on understanding of Volatility, we shall investigate a forensic case and use it to learn about the tool's inner workings. The files for the analysis are found under the `Desktop/Investigations` directory.

#### Case 001

Your SOC has informed you that they have gathered a memory dump from a quarantined endpoint thought to have been compromised by a banking trojan masquerading as an Adobe document. Your job is to use your knowledge of threat intelligence and reverse engineering to perform memory forensics on the infected host.

You have been informed of a suspicious IP in connection with the file `Investigation-1.vmem` that could be helpful: `41.168.5.140`.

#### Plugins

Volatility uses plugins to request data to carry out analysis. Some of the most commonly used plugins include:

- `windows.info`
- `linux.info`
- `pslist`
- `pstree`

Let us look at these plugins, extracting information from our memory file. First, we can begin by obtaining operating system details from the image. In previous versions of Volatility, this information was identified as **OS profiles** and was extracted using the plugin `imageinfo`. However, OS profiles have been deprecated in the new version, and now we have the individual information plugins.

Given that our memory file was obtained from a Windows VM running on VMware, we can extract details about its profile with the command below:

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

We can extract the system version, architecture, symbol tables, and available memory layers from the details.

:::info Answer the questions below

<details>

<summary> What is the build version of the host machine in Case 001? </summary>

```plaintext
2600.xpsp.080413-2111
```

</details>

<details>

<summary> At what time was the memory file acquired in Case 001? </summary>

```plaintext
2012-07-22 02:45:08
```

</details>

:::

## Task 4 Listing Processes and Connections

When we want to analyse details on processes and network connections from our memory file, Volatility supports different plugins, each with varying techniques used. Not all plugins mentioned here will produce a result from the memory file, as the capture may not have included processes or services that the plugins would enumerate.

### Active Process Enumeration

The most basic way of listing processes is by using `pslist`. This plugin enumerates active processes from the doubly-linked list that keeps track of processes in memory, equivalent to the process list in the task manager. The output from this plugin will include all current and terminated processes and their exit times.

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.pslist
```

### Hidden Process Enumeration

Some malware, typically rootkits, will, in an attempt to hide their processes, unlink themselves from the list. By unlinking themselves from the list, you will no longer see their processes when using `pslist`. To combat this evasion technique, we can use `psscan`. This technique of listing processes will locate processes by finding data structures that match `_EPROCESS`. While this technique can help with evasion countermeasures, it can also result in false positives; therefore, we must be careful.

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.psscan
```

### Process Hierarchy Enumeration

The third process plugin, `pstree`, does not offer any other kind of special techniques to help identify evasion like the last two plugins. However, this plugin will list all processes based on their parent process ID, using the same methods as `pslist`. This can be useful for an analyst to get a complete story of the processes and what may have occurred at the extraction time.

```shell title="Volatility Process Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.pstree
```

### File, Registry, and Thread Enumeration

Inspecting files and the registry is also vital during a memory forensic investigation. We can use the plugin `handles` to look into the details and handles of files and threads from a host.

```shell title="Volatility Files Inspecting"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.handles
```

### Network Connection Enumeration

Now that we know how to identify processes, we also need to have a way to identify the network connections present at the time of extraction on the host machine. The `netstat` will attempt to identify all memory structures with a network connection.

```shell title="Volatility Network  Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.netstat
```

It is worth noting that this command in the current state of Volatility 3 can be very unstable, particularly around old Windows builds. To combat this, you can utilise other tools like [bulk_extractor](https://tools.kali.org/forensics/bulk-extractor) to extract a PCAP file from the memory file. Sometimes, this is preferred in network connections that you cannot identify from Volatility alone.

### TCP/UDP Socket Enumeration

We can also identify network sockets and their linked processes from a memory file. To do this, we can use the plugin `netscan`. This will recover active and closed TCP/UDP connections, associated process IDs, local and remote ports, and IPs using memory pool scanning.

```shell title="Volatility TCP/UDP Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.netscan
```

### DLL Enumeration

The last plugin we will cover is `dlllist`. This plugin will list all DLLs associated with processes at extraction time. This can be especially useful once you have analysed further and filtered the output to a specific DLL that might indicate a specific type of malware you believe to be on the system.

```shell title="Volatility DLL Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.dlllist
```

:::info Answer the questions below

<details>

<summary> What is the absolute path to the active Adobe process? </summary>

```plaintext
C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe
```

</details>

<details>

<summary> What is the parent process of this process in Case 001? </summary>

```plaintext
explorer.exe
```

</details>

<details>

<summary> What is the PID of the parent process? </summary>

```plaintext
1484
```

</details>

<details>

<summary> How many DLL files are used by the Adobe process that are outside the `system32` directory? </summary>

```plaintext
3
```

</details>

<details>

<summary> What is the name of the one KeyedEvent associated with the process's handles? </summary>

```plaintext
CritSecOutOfMemoryEvent
```

</details>

:::

## Task 5 Volatility Hunting and Detection Capabilities

Advanced threats can execute solely in memory, avoiding disk artefacts. Volatility offers many plugins that can aid in your hunting and detection capabilities when hunting for injected code and malware, as well as applying custom detection rules via YARA.

Before going through this section, it is recommended that you have a basic understanding of how evasion techniques and various malware techniques are employed by adversaries, as well as how to hunt and detect them.

### Malware Analysis

The first plugin we will discuss, which is one of the most useful when hunting for code injection, is `malfind`. This plugin will attempt to detect injected processes and their PIDs along with the offset address and the infected area's Hex, Ascii, and Disassembly views. The plugin works by scanning the heap and identifying processes that have the executable bit set **RWE** or **RX** and/or no memory-mapped file on disk (file-less malware).

Based on what `malfind` identifies, the injected area will change. An MZ header is an indicator of a Windows executable file. The injected area could also be directed towards shellcode, which requires further analysis.

![File structure of a Windows executable, showing the MZ header value.](img/image_20251207-210748.png)

```shell title="Volatility Malware Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.malfind
```

Another helpful plugin is `vadinfo`. This displays detailed information about virtual memory descriptors, which is useful when manually investigating suspicious memory regions and heap allocations.

```shell title="Volatility Malware Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.vadinfo
```

:::info Answer the questions below

<details>

<summary> What processes in the Case 001 memory file contain a header that points to a Windows executable file? (Answer: process1,process2) </summary>

```plaintext
explorer.exe,reader_sl.exe
```

</details>

:::

## Task 6 Advanced Memory Forensics

Forensic analysts must be equipped to detect manipulation deep within the operating system when dealing with sophisticated threats such as kernel-mode rootkits. Rootkits are designed to conceal processes, files, drivers, and their presence by modifying kernel structures. This section focuses on a structured and practical exploration of these advanced evasion techniques, particularly within the Windows operating system, using Volatility 3.

Advanced adversaries often employ **hooking** — a technique that allows malicious software to intercept and potentially redirect system-level functions for evasion or persistence. Hooks are not inherently malicious; antivirus and debugging tools also use them legitimately. The analyst’s responsibility is to identify whether the presence of a hook aligns with expected system behaviour or represents malicious interference.

One of the most common hooking strategies is the **System Service Descriptor Table (SSDT)** hooks. These hooks are used to modify kernel system call table entries. They are prevalent in kernel-mode malware, with Volatility providing a corresponding plugin for analysis.

### SSDT Hook Detection

The Windows kernel uses the **System Service Descriptor Table (SSDT)** to resolve addresses for system calls. Rootkits often overwrite SSDT entries to redirect legitimate system calls (e.g., `NtCreateFile`) to their malicious counterparts.

Volatility 3’s `windows.ssdt` plugin enables analysts to inspect this table for any irregularities.

```shell title="Volatility SSDT Hook Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.ssdt
```

**Recommendation**: Perform SSDT inspection **after** discovering suspicious kernel modules or abnormal process behaviour.

### Kernel Module Enumeration

The `windows.modules` plugin lists drivers and kernel modules currently loaded into memory. Each entry includes metadata such as base address, size, and file path.

```shell title="Volatility Kernel Module Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.modules
```

### Driver Scanning

While `windows.modules` lists known drivers, it can miss hidden or unlinked ones. The `windows.driverscan` plugin scans raw memory for DRIVER_OBJECT structures that may have been unlinked from standard lists.

```shell title="Volatility Kernel Module Enumeration"
ubuntu@tryhackme:~/Desktop/volatility3$ python3 vol.py -f ~/Desktop/Investigations/Investigation-1.vmem windows.driverscan
```

**Tip**: Use this plugin if you suspect DKOM (Direct Kernel Object Manipulation) or rootkit behaviour.

:::info Answer the questions below

<details>

<summary> What is the address for the `NtCreateFile` system call? </summary>

```plaintext
0x8056e27c
```

</details>

:::

## Task 7 Practical Investigations

### Case 002

You have been informed that your corporation has been hit with a chain of ransomware that has been affecting corporations internationally. Your team has already recovered from the attack through backups. Your job is to perform post-incident analysis and identify which actors were at play and what occurred on your systems. You have received a raw memory dump from your team to begin your analysis.

The memory file is located in `~/Desktop/Investigations/Investigation-2.raw`.

:::info Answer the questions below

<details>

<summary> What suspicious process is running at PID 740? </summary>

```plaintext
@WanaDecryptor@
```

</details>

<details>

<summary> What is the full path of the suspicious binary in PID 740? </summary>

```plaintext
C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
```

</details>

<details>

<summary> What is the parent process of PID 740? </summary>

```plaintext
tasksche.exe
```

</details>

<details>

<summary> From our current information, what malware is present on the system? </summary>

```plaintext
Wannacry
```

</details>

<details>

<summary> What plugin could be used to identify all files loaded from the malware working directory? </summary>

```plaintext
windows.filescan
```

</details>

:::

## Task 8 Conclusion

We have only covered a very thin layer of memory forensics with Volatility, which can go much deeper when analysing the Windows, Mac, and Linux architectures. If you're looking for a deep dive into memory forensics, I suggest reading **The Art of Memory Forensics**.

Additionally, the following is a list of worthy plugin mentions that you can be aware of and read more on:

- `windows.callbacks`: Malware may register malicious callbacks for process creation, image loading, or thread creation. We can use this plugin to inspect callback functions for unknown driver associations or non-standard modules.
- `windows.driverirp`: This plugin examines IRP (I/O Request Packet) dispatch tables of drivers. Suspicious drivers may register no IRP functions or point to non-driver memory.
- `windows.modscan`: This plugin scans for loaded kernel modules without relying on linked lists. It can be used to uncover stealth drivers that evade both `modules` and `driverscan`.
- `windows.moddump`: This plugin allows analysts to extract suspicious drivers or modules from memory for static analysis. Further investigation with tools such as Ghidra or IDA can be done to reverse engineer dumped modules.
- `windows.memmap`: This plugin can perform deeper analysis of injected code or memory artefacts, to extract memory regions from specific processes.
- `yarascan`: This plugin will search for strings, patterns, and compound rules against a rule set by using a YARA file as an argument or listing rules within the command line.

In the next room, [Memory Acquisition](https://tryhackme.com/room/memoryacquisition), we will cover memory acquisition in detail, covering all the necessary techniques and approaches.

:::info Answer the questions below

<details>

<summary> Read the above and continue learning! </summary>

```plaintext
No answer needed
```

</details>

:::
