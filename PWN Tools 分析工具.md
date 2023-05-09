# PWN Tools | 分析工具

## 第 1 章 IDA Pro

### 1.1 简介

IDA Pro 即专业交互式反编译器（Interactive Disassembler Professional），是 Hex-Rays 公司的商业产品，也是二进制研究人员的常用工具之一。

除 IDA Pro 外，功能类似的工具还有 Binary Ninja、JEB、Ghidra 等。

线性扫描和递归下降扫是两种主要的反汇编算法。GDB 采用的是线性扫描算法，而 IDA 采用的是递归下降算法，其主要优点是基于控制流，区分代码和数据的能力更强，很少会在反汇编过程中错误地将数据值作为代码处理。

### 1.2 基本操作

#### 1.2.1 目录结构

IDA 的目录结构如下：

- cfg：包含各种配置文件，包括 IDA 基础配置文件 ida.cfg、GUI 配置文件 idagui.cfg 和文本模式用户界面配置文件 idatui.cfg。
- dbgsrv：包含远程调试的 server 端，包括 Android、macOS、Windows、Linux 等操作系统以及不同架构的调试器。
- idc：包含 IDA 内置脚本语言 idc 所需的核心文件。
- ids：包含一些符号文件（IDA 语法中的 IDS 文件），这些文件用于描述可被加载到 IDA 的二进制文件引用的共享库的内容。这些项目包含描述某个函数所需的参数类型和数量的信息、函数的返回类型（如果有）以及与该函数的调用约定有关的信息。
- loaders：包含在文件加载过程中用于识别和解析 PE/ELF 等已知文件格式的 IDA 扩展。
- platforms：包含 QT 的一个运行时库 qwindows.dll。
- plugins：插件安装目录。
- procs：包含所支持的处理器模块，提供了从机器语言到汇编语言的转换能力，并负责生成在 IDA 用户界面中显示的汇编代码。
- python：支持 64 位的 Python，包含 IDAPython 相关的库文件。
- sig：包含在各种模式匹配操作中利用的签名。通过模式匹配，IDA 能够将代码序列确定为已知的库代码，从而节省大量的分析时间。这些签名通过 IDA 的”快速的库识别和鉴定技术“（FLIRT）生成。
- til：包含一些类型库信息，记录了特定编译器库的数据结构。

![image-20230509115624369](images/image-20230509115624369.png)

#### 1.2.2 菜单结构

最上方为 IDA 菜单栏。IDA 的菜单结构如下：

- File：进行打开辅助脚本、导出 idc、创建档期那数据库快照等操作。
- Edit：修改 IDA 数据库，或者使用插件。
- Jump：跳转至指定位置。
- Search：搜索字符串、函数名等信息。
- View：打开不同的子窗口。
- Debugger：指定调试器来动态调试当前加载的可执行文件。
- Options：对 IDA 进行一些设置。
- Windows：调整当前显示的窗口。
- Help：打开帮助文件。

反汇编窗口也叫 IDA-View 窗口，有两种显示格式：默认的图形视图和面向文本的列表视图，使用快捷键”空格“进行切换。

函数的控制流图由许多个基本块构成，基本块之间用不同颜色的箭头连接：

- 蓝色箭头：执行下一个基本块。
- 红色箭头：跳转到判断条件为假的分支。
- 绿色箭头：跳转到判断条件为真的分支。

交叉引用是 IDA 最强大的功能之一，有两种类型：代码交叉引用和数据交叉引用。首先选择一个函数，使用交叉引用（快捷键 X）可以快速地找到该函数被调用的地方。同理，选择一个数据，也可以快速找到该数据被使用的位置。

点击 Options 菜单的 general 可以对显示的内容进行调整，例如 Line prefixes（graph）给控制流图加上地址，Auto comments 给指令加上注释。

#### 1.2.3 数据库文件

在 IDA 进行分析的过程中会创建一个数据库，其组件分别保存在 4 个文件中，这些文件的名称与可执行文件名相同，扩展名分别是 .id0、.id1、.nam、.til。

- .id0：是一个二叉树形式的数据库。
- .id1：包含了描述每个程序字节的标记。
- .nam：包含与 IDA 的 Names 窗口中显示的给定程序位置有关的索引信息。
- .til：用于存储一个给定数据库的本地类型定义有关的信息。

以上文件直到关闭 IDA 时才会让用户选择是否将其打包保存。32 位的 IDA 以 idb 格式保存数据库，64 位的 IDA以 i64 格式保存数据库。保存数据库时的选项含义如下：

- Don't pack database：不打包数据库。该选项仅仅刷新对 4 个数据库组件文件所做的更改，在关闭桌面前并不创建 IDB 文件。
- Pack database(Store)：打包数据库（存储）。该选项会将 4 个数据库组件文件存到一个 IDB 文件中。之前的任何 IDB 不经确认即被覆盖，另外，该选项不会进行压缩。
- Pack database(Deflate)：打包数据库（压缩）。该选项等同于 Store 选项，唯一的差别在于会进行压缩。
- Collect garbage：收集垃圾。勾选后 IDA 会在关闭数据库之前，从数据库中删除任何没有用的内存页。同时，如果选择 Deflate 选项，可以创建尽可能小的 IDB 文件。
- DON'T SAVE the database：不保存数据库。该选项不会保存数据库文件，有时这是撤销备份的唯一选择。注意，IDA 对数据库文件没有撤销操作，因此需要做好备份，并且谨慎操作，也可以使用 File 菜单的 take database snapshot 对数据库做快照。

### 1.3 远程调试

IDA Pro 是一个反汇编器，也是一个调试器，支持 Windows 32/64-bit、Linux 32/64-bit、OSX x86/x64、IOS、Android 等平台的本地或者远程调试。

远程调试是通过 TCP/IP 网络在本地机器上调试远程机器上的程序，因此需要两部分组件：

- 客户端：运行 IDA 的机器。
- 服务端：运行目标程序的机器。

以下为 IDA 自带的服务端程序，其他平台可以通过 gdbserver 进行扩展：

| File name          | Target system      | Debugged programs   |
| ------------------ | ------------------ | ------------------- |
| android_server     | ARM Android        | 32-bit ELF files    |
| android_server64   | AArch64 Android    | 64-bit ELF files    |
| android_x64_server | x86 Android 32-bit | 32-bit ELF files    |
| android_x86_server | x86 Android 64-bit | 64-bit ELF files    |
| armlinux_server    | ARM Linux          | 32-bit ELF files    |
| linux_server       | Linux 32-bit       | 32-bit ELF files    |
| linux_server64     | Linux 64-bit       | 64-bit ELF files    |
| mac_server         | Mac OS X           | 32-bit Mach-O files |
| mac_server64       | Mac OS X           | 64-bit Mach-O files |
| win32_remote.exe   | MS Windows 32-bit  | 32-bit PE files     |
| win64_remote64.exe | MS Windows 64-bit  | 64-bit PE files     |

#### 1.3.1 使用 IDA 的 Linux 服务端程序

将 linux_server64 复制到 Linux 中启动运行，默认在本地 23946 端口进行监听：

```
$ ./linux_server64 --help
IDA Linux 64-bit remote debug server(ST) v7.5.26. Hex-Rays (c) 2004-2020
Usage: linux_server64 [options]
  -p ...  (--port-number ...) Port number
  -i ...  (--ip-address ...) IP address to bind to (default to any)
  -s      (--use-tls) Use TLS
  -c ...  (--certchain-file ...) TLS certificate chain file
  -k ...  (--privkey-file ...) TLS private key file
  -v      (--verbose) Verbose mode
  -P ...  (--password ...) Password
  -k      (--on-broken-connection-keep-session) Keep debugger session alive when connection breaks
  -K      (--on-stop-kill-process) Kill debuggee when closing session
```

```
$ ./linux_server64 
IDA Linux 64-bit remote debug server(ST) v7.5.26. Hex-Rays (c) 2004-2020
Listening on 0.0.0.0:23946...
```

点击 IDA 的 Debugger 菜单栏，选择 Remote Linux debugger，在 Process options 窗口中输入服务端文件路径、IP、端口等信息。点击 Start Process 启动进程（点击 attach to process 则可以调试正在运行的进程），IDA 会自动将目标程序发送到服务端相同路径下运行，并触发断点，在 debug 模式主窗口可以看到程序指令、寄存器、共享库、线程以及栈等信息。

#### 1.3.2 使用 gdbserver

将目标程序绑定到 0.0.0.0:6666 端口，客户端设置同上。

```
$ gdbserver 0.0.0.0:6666 ./fsb
Process ./fsb created; pid = 3757
Listening on port 6666
```

```
$ gdbserver --multi 0.0.0.0:6666		# 不指定目标程序
$ gdbserver --multi 0.0.0.0:6666 --attach 3757		# 指定目标程序 PID
```

### 1.4 常用插件

对于 Windows 系统 IDA Pro 插件的安装，一般情况只需要把 dll/python 文件复制到 plugins 目录下即可，对于一些复杂的插件，按照官方文档安装。

- FRIEND：提供了指令和寄存器的文档查看功能。
- BinCAT：静态二进制代码分析工具包，通过追踪寄存器和内存值，可以进行污点分析、类型识别和传播、前后向切片分析等。
- BinDiff：用于二进制文件分析和对比，快速发现汇编代码的差异或相似之处，常用于分析 patch、病毒变种等。
- Keypatch：利用 keystone 框架修改二进制可执行文件。
- heap-viewer：漏洞利用开发辅助插件，主要关注 Linux glibc（ptmalloc2）的堆管理实现，辅助解决 CTF Pwn 题目。
- deREferencing：重写了 IDA 在调试时的寄存器和栈窗口，增加了指针解引用的数据显示，类似 GDB 插件 PEDA/GEF。
- IDArling：解决多个用户在同一个数据库上协同工作的问题。

## 第 2 章  GDB

## 第 3 章 其他常用工具

