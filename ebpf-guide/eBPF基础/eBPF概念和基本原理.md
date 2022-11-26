# eBPF概念和基本原理

大约一年前，有个朋友想要用 Rust 开发一个 EVM Assembler。在他的一再要求之下，我开始帮忙编写单元测试。那时候我还不大了解操作系统的相关知识，只好开始学习一些语法和词法方面的东西。很快这个事情就无以为继了，然而我对操作系统有了一些整体了解。之后他对 eBPF 赞赏有加时，我觉得我的春天又来了。

eBPF 的门槛有点高，有 500 字的小品，也有 Cilium 铺天盖地的文档。我编写本文的目的，是针对这一新技术读者提供一个全面的入门介绍，用户可以以此为基础，进行进一步的探索。后续可以阅读 Linux Weekly News、Brenden Gregg 的网站 以及 Cilium 文档学习更多相关知识。本文设计的内容包括：

- eBPF 的用处
- eBPF 的原理
- eBPF 的实例
- 如何开始使用 eBPF

## eBPF 的用处

有了 eBPF，无需修改内核，也不用加载内核模块，程序员也能在内核中执行自定义的字节码。eBPF 和内核紧密联系，下面先介绍一些相关的基本概念。

Linux 系统分为内核空间和用户空间。内核空间是操作系统的核心，对所有硬件都具备不受限制的完整的访问能力，例如内存、存储以及 CPU 等。内核既然具备了这样的超级权限，势必需要严加保护，仅允许运行最可靠的代码。而用户空间运行的就是非内核的进程——例如 I/O、文件系统等。这些进程仅能通过内核开放的系统调用，对硬件进行有限的访问。换句话说，用户空间的程序一定要经过内核空间的过滤。



系统调用接口能够满足绝大多数需要，开发者在面对新的硬件、文件系统、网络协议甚至自定义的系统调用时，还是需要更多的弹性的。在不修改内核源码的情况下，用户代码要直接访问硬件怎么办呢？可以使用 Linux 内核模块（LKM）。用户空间一般是需要通过系统调用来访问内核空间，而 LKM 是直接加载到内核的，是内核的一部分。LKM 最有价值的特点之一，就是可以在运行时加载，不用编译内核也不用重启机器。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102208153.png?imageView2/0/format/webp/q/75)

LKM 非常有用，但是也引入了很多风险。内核和用户空间不同，要进行不同的安全考量。内核空间是为了操作系统内核这样的特权代码准备的。系统调用连接了内核和用户空间，让用户空间能够对硬件进行合适的操作。换个说法，LKM 是能够让内核崩溃的。模块和内核的紧密关系，使得安全和升级成本直线升高。

### eBPF 是什么

eBPF 是一个用于访问 Linux 内核服务和硬件的新方法。这一新技术已经用于网络、出错、跟踪以及防火墙等方面。

`dtrace` 是一个 Solaris 和 BSD 操作系统上的动态跟踪工具，eBPF 受到 `dtrace` 的启发，原意是设计一个更好的 Linux 跟踪工具。跟 `dtrace` 不同的是，Linux 无法获取运行中系统的鸟瞰视图，它被系统调用、库调用以及函数所限制。一小撮工程师在 Berkeley Packet Filter（BPF）基础之上，构建一个内核虚拟机级别的包过滤机制，提供了类似 `dtrace` 的功能。2014 年第一个版本适配了 Linux 3.18，提供的功能相对较少。要使用完整的 eBPF，需要 Linux 4.4 或以上。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102216871.png?imageView2/0/format/webp/q/75)

上图对 eBPF 架构进行了一个简单的展示。eBPF 程序需要满足一系列的需求，才能被加载到内核。Verifier 中有一万多行代码用来对 eBPF 程序进行检查。Verifier 会遍历对 eBPF 程序在内核中可能的执行路径进行遍历，确保程序能够在不出现导致内核锁定的循环的情况下运行完成。除此之外还有其它必须满足的检查，例如有效的寄存器状态、程序大小以及越界等。安全控制方面，eBPF 和 LKM 是颇有差异的。

如果所有的检查都通过了，eBPF 程序被加载并编译到内核中，并监听特定的信号。该信号以事件的形式出现，会被传递给被加载的 eBPF 程序。一旦被触发，字节码就会根据其中的指令执行并收集信息。



所以 eBPF 到底做了什么？程序员能够在不增加或者修改内核代码的情况下，就能够在 Linux 内核中执行自定义的字节码。虽说还远不能整体取代 LKM，eBPF 程序可以自定义代码来和受保护的硬件资源进行交互，对内核的威胁最小。

## eBPF 的机制

前面介绍了 eBPF 的基础架构。这些能力是由多个组件协同实现的，每一种都有自己的复杂度。

### eBPF 程序剖析

#### 事件和钩子

eBPF 程序是在内核中被事件触发的。在一些特定的指令被执行时时，这些事件会在钩子处被捕获。钩子被触发就会执行 eBPF 程序，对数据进行捕获和操作。钩子定位的多样性正是 eBPF 的闪光点之一。例如下面几种：

- 系统调用：当用户空间程序通过系统调用执行内核功能时。
- 功能的进入和退出：在函数退出之前拦截调用。
- 网络事件：当接收到数据包时。
- kprobe 和 uprobe：挂接到内核或用户函数中。

#### 辅助函数

eBPF 程序被触发时，会调用辅助函数。这些特别的函数让 eBPF 能够有访问内存的丰富功能。例如 Helper 能够执行一系列的任务：

- 在数据表中对键值对进行搜索、更新以及删除。
- 生成伪随机数。
- 搜集和标记隧道元数据。
- 把 eBPF 程序连接起来，这个功能被称为 `tail call`。
- 执行 Socket 相关任务，例如绑定、获取 Cookie、数据包重定向等。

这些助手函数必须是内核定义的，换句话说，eBPF 程序的调用能力是受到一个白名单限制的。这个名单很长，并且还在持续增长之中。

#### Map

要在 eBPF 程序和内核以及用户空间之间存储和共享数据，eBPF 需要使用 Map。正如其名，Map 是一种键值对。Map 能够支持多种数据结构，eBPF 程序能够通过辅助函数在 Map 中发送和接收数据。

### 执行 eBPF 程序

#### 加载和校验

所有 eBPF 程序都是以字节码的形式执行的，因此需要有办法把高级语言编译成这种字节码。eBPF 使用 LLVM 作为后端，前端可以介入任何语言。因为 eBPF 使用 C 编写的，所以前端使用的是 Clang。但在字节码被 Hook 之前，必须通过一系列的检查。在一个类似虚拟机的环境下用内核 Verifier阻止带有循环、权限不正确或者导致崩溃的程序运行。如果程序通过了所有的检查，字节码会使用 `bpf()` 系统调用被载入到 Hook 上。

#### JIT 编译器

校验结束后，eBPF 字节码会被 JIT 编译器转译成本地机器码。eBPF 是 64 位编码，共有 11 个寄存器，因此 eBPF 和 x86、ARM 以及 arm64 等硬件都能紧密对接。虽然 eBPF 受到 VM 限制，JIT 过程保障了它的运行性能。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102227295.png?imageView2/0/format/webp/q/75)

### 总结

上面的概念们放在一起，eBPF 程序通过安全检查后插入钩子，被事件触发之后，程序会启动执行，用辅助函数和 Map 来对数据进行存储和操作。下一届我们来研究一下它们的协同方式。

## 一个例子

在 Gravitational 有一个叫做 Teleport 的开源项目，其中使用了 eBPF 程序进行跟踪和网络操作。有的组织希望知道 SSH 会话中发生了什么，Teleport 提供 SSH 访问途径的同时，加入了对用户行为的记录。可以通过对命令编码、在 Shell 脚本中运行命令的方式来进行混淆，从而阻碍对会话的记录。

Teleport 4.2 中，我们引入了会话记录，其中用了三个 eBPF 程序来获取 SSH 会话，并将其转化为结构化的事件。



例如 `echo Y3VybCBodHRwOi8vd3d3LmV4YW1wbGUuY29tCg== | base64 --decode | sh`，我们能够在终端抓取到这个命令，但是这并无意义，用户已经对命令进行了混淆，但是有了 eBPF，我们就能知道，用户试图隐藏的是 `curl`：

```
{
  "event": "session.command",
  "path": "/bin/sh",
  "program": "sh",
  "argv": [],
  "login": "centos",
  "user": "jsmith"}
{
  "event": "session.command",
  "path": "/bin/base64",
  "program": "base64",
  "argv": [    "--decode"
  ],
  "login": "centos",
  "user": "jsmith"}
{
  "event": "session.command",
  "path": "/bin/curl",
    "argv": [    "http://www.example.com"
  ],
  "program": "curl",
  "return_code": 0,
  "login": "centos",
  "user": "jsmith"}
{
  "event": "session.network",
  "program": "curl",
  "src_addr": "172.31.43.104",
  "dst_addr": "93.184.216.34",
  "dst_port": 80,
  "login": "centos",
  "user": "jsmith",
  "version": 4}
```

借助 eBPF 的能力，我们把这种混淆行为转换为事件流，便于导出和分析。Teleport 用 `execsnoop`、`opensnoop` 以及 `tcpconnect` 来恢复这些事件。特别会关注的是 `tcpconnect`，它最终将信息以 JSON 的形式返回来。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102240499.png?imageView2/0/format/webp/q/75)

`tcpconnect` 会跟踪 TCP 连接。像 Teleport 这样用 SSH 证书管理访问的工具来说，必须要知道 TCP 连接的发起情况。`tcpconnect` 能跟踪 `connect()` 系统调用，该调用会在 Socket 上初始化一个连接。要对这个情况进行跟踪，tcpconnect 在内核中插入了一个 `kprobe`，能够动态进入任何例程：

```
# initializeBPF b = BPF(text=bpf_text) b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry") b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
```

程序被触发以后，`tcpconnect` 会开始输出信息，下表展示的就是这样的信息：

```
$ ./tcpconnect
PID   COMM  SADDR             DADDR           DPORT
-----------------------------------------------------
2315  curl  172.31.43.104     93.184.216.34   80
```

所有这些数据都是用辅助函数收集而来。如果看看 Python 代码，会发现 `tcpconnect` 试用了来自 bcc 的 BPF 库的辅助函数来对上述输出内容进行格式化。

```
...struct ipv4_data_t data4 = {.pid = pid, .ip = ipver}; 
data4.saddr = skp->__sk_common.skc_rcv_saddr; 
data4.daddr = skp->__sk_common.skc_daddr; 
data4.dport = ntohs(dport); 
bpf_get_current_comm(&data4.task, sizeof(data4.task));
...
```

## eBPF 入门

行文至此，我希望读者已经对 eBPF 有了一个最基础的了解，知道了他的重要性以及基本原理。是时候浏览更多技术文档和文章了。本文中提供了不少链接，不过这里最推荐的是 Quinten Monnet 的博客。

自行编写代码，开发自己的 eBPF 可能有点难。但是很多开源的开发工具链正在涌现，简化了很多 eBPF 的相关场景。下面介绍几个最流行的：

- BCC：BCC 是一个工具包用于创建高效的内核跟踪和处理程序，并包含了很多有用的工具和示例。BCC 简化了 BPF 程序的开发，内核指令使用 C 指令（包含了 LLVM 的封装），前端使用的是 Python 和 LUA。BCC 有很多用途，例如性能分析和网络流量控制。BCC 还为其它程序提供了 API。
- bpftrace：BPFtrace 是一个高级跟踪语言，用 LLVM 作为后端把脚本编译为 BPF 字节码，并用 BCC 和 Linux BPF 系统进行交互，并支持现有的 Linux 跟踪能力：kprobe、uprobe 以及 `tracepoint`。
- Go、C/C++ 以及 Rust 的通用库。

## 结论

eBPF 还是个很新鲜的技术，让程序员在不修改内核空间的情况下，能够在内核中执行自定义的字节码并从内核函数中获取更多信息。原本这些目标需要通过系统调用或内核模块来完成，eBPF 降低了所需的复杂度和危险性。简单来说，eBPF 的工作流程：

- 把 eBPF 程序编译成字节码。
- 在载入到 Hook 之前，在虚拟机中对程序进行校验。
- 把程序附加到内核之中，被特定事件触发。
- JIT 编译。
- 在程序被触发时，调用辅助函数处理数据。
- 在用户空间和内核空间之间使用键值对共享数据。

## 推荐阅读

- SCP - Familiar, Simple, Insecure, and Slow
- Greed is Good: Creating Teleport’s Discovery Protocol
- Gracefully Restarting a Go Program Without Downtime

## 相关链接

- **What is eBPF and How Does it Work?**：`https://gravitational.com/blog/what-is-ebpf/`
- **Virag Mody**：`https://www.linkedin.com/in/virag-mody-650974a9`
- **EVM Assembler**：`https://medium.com/mycrypto/the-ethereum-virtual-machine-how-does-it-work-9abac2b7c9e`
- **Cilium**：`https://cilium.io/`
- **Linux Weekly News**：`https://lwn.net/Articles/740157/`
- **Brenden Gregg 的网站**：`http://www.brendangregg.com/index.html`
- **Cilium 文档**：`https://docs.cilium.io/en/stable/bpf/`
- **Linux 内核模块（LKM）**：`https://tldp.org/LDP/lkmpg/2.6/html/lkmpg.html`
- **what is ebpf 1**：`image/what-is-ebpf-1.png`
- **what is ebpf 2**：`images/what-is-ebpf-2.png`
- **Verifier**：`https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c`
- **名单**：`https://man7.org/linux/man-pages/man7/bpf-helpers.7.html`
- **LLVM**：`https://llvm.org/`
- **Clang**：`https://clang.llvm.org/`
- **内核 Verifier**：`https://elixir.bootlin.com/linux/latest/source/kernel/bpf/verifier.c`
- **what-is-ebpf-3.png**：`images/what-is-ebpf-3.png`
- **Teleport**：`https://gravitational.com/teleport`
- **Teleport 4.2**：`https://gravitational.com/blog/teleport-release-4-2`
- **what-is-ebpf-4.png**：`images/what-is-ebpf-4.png`
- **Python 代码**：`https://github.com/iovisor/bcc/blob/ec3747ed6b16f9eec36a204dfbe3506d3778dcb4/tools/tcpconnect.py`
- **bcc 的 BPF 库**：`https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h`
- **Quinten Monnet**：`https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/`
- **BCC**：`https://github.com/iovisor/bcc`
- **bpftrace**：`https://github.com/ajor/bpftrace`
- **Go**：`https://github.com/iovisor/gobpf`
- **C/C++**：`https://github.com/libbpf/libbpf`
- **Rust**：`https://github.com/redsift/redbpf`
- **SCP - Familiar, Simple, Insecure, and Slow**：`https://gravitational.com/blog/scp-familiar-simple-insecure-slow/`
- **Greed is Good: Creating Teleport’s Discovery Protocol**：`https://gravitational.com/blog/teleport-discovery-protocol/`
- **Gracefully Restarting a Go Program Without Downtime**：`https://gravitational.com/blog/golang-ssh-bastion-graceful-restarts/`

文章转载自伪架构师。[点击这里阅读原文了解更多](https://mp.weixin.qq.com/s?__biz=MzIxMDY5ODM1OA==&mid=2247485238&idx=1&sn=c4a2be9542210f51506fac520b540c5d&scene=21#wechat_redirect)。