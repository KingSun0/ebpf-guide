# eBPF技术背景

**发展历史**

BPF，是类 Unix 系统上数据链路层的一种原始接口，提供原始链路层封包的收发。1992 年，Steven McCanne 和 Van Jacobson 写了一篇名为《The BSD Packet Filter: A New Architecture for User-level Packet Capture[2]》的论文。在文中，作者描述了他们如何在 Unix 内核实现网络数据包过滤，这种新的技术比当时最先进的数据包过滤技术快 20 倍。

![img](https://996station.com/wp-content/uploads/2022/11/20221126103914383.png?imageView2/0/format/webp/q/75)

BPF 在数据包过滤上引入了两大革新：

- 一个新的虚拟机 (VM) 设计，可以有效地工作在基于寄存器结构的 CPU 之上
- 应用程序使用缓存只复制与过滤数据包相关的数据，不会复制数据包的所有信息，这样可以最大程度地减少BPF 处理的数据

由于这些巨大的改进，所有的 Unix 系统都选择采用 BPF 作为网络数据包过滤技术，直到今天，许多 Unix 内核的派生系统中（包括 Linux 内核）仍使用该实现。tcpdump 的底层采用 BPF 作为底层包过滤技术，我们可以在命令后面增加 -d 来查看 tcpdump 过滤条件的底层汇编指令。

```
$ tcpdump -d 'ip and tcp port 8080'
(000) ldh      [12]
(001) jeq      #0x800           jt 2 jf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4 jf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12 jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x1f90          jt 11 jf 9
(009) ldh      [x + 16]
(010) jeq      #0x1f90          jt 11 jf 12
(011) ret      #262144
(012) ret      #0
```

2014 年初，Alexei Starovoitov 实现了 eBPF（extended Berkeley Packet Filter）。经过重新设计，eBPF 演进为一个通用执行引擎，可基于此开发性能分析工具、软件定义网络等诸多场景。

eBPF 最早出现在 3.18 内核中，此后原来的 BPF 就被称为经典 BPF，缩写 cBPF（classic BPF），cBPF 现在已经基本废弃。现在，Linux 内核只运行 eBPF，内核会将加载的 cBPF 字节码透明地转换成 eBPF 再执行。

**eBPF 与 cBPF**

eBPF 新的设计针对现代硬件进行了优化，所以 eBPF 生成的指令集比旧的 BPF 解释器生成的机器码执行得更快。扩展版本也增加了虚拟机中的寄存器数量，将原有的 2 个 32 位寄存器增加到 10 个 64 位寄存器。

由于寄存器数量和宽度的增加，开发人员可以使用函数参数自由交换更多的信息，编写更复杂的程序。总之，这些改进使 eBPF 版本的速度比原来的 BPF 提高了 4 倍。

| 维度           | cBPF                      | eBPF                                                         |
| -------------- | ------------------------- | ------------------------------------------------------------ |
| 内核版本       | Linux 2.1.75（1997 年）   | Linux 3.18（2014 年）[4.x for kprobe/uprobe/tracepoint/perf-event] |
| 寄存器数目     | 2 个：A，X                | 10个：R0–R9，另外 R10 是一个只读的帧指针R0：eBPF 中内核函数的返回值和退出值R1 - R5：eBF 程序在内核中的参数值R6 - R9：内核函数将保存的被调用者callee保存的寄存器R10：一个只读的堆栈帧指针 |
| 寄存器宽度     | 32 位                     | 64 位                                                        |
| 存储           | 16 个内存位: M[0–15]      | 512 字节堆栈，无限制大小的 map 存储                          |
| 限制的内核调用 | 非常有限，仅限于 JIT 特定 | 有限，通过 bpf_call 指令调用                                 |
| 目标事件       | 数据包、 seccomp-BPF      | 数据包、内核函数、用户函数、跟踪点 PMCs 等                   |

2014 年 6 月，eBPF 扩展到用户空间，这也成为了 BPF 技术的转折点。正如 Alexei 在提交补丁的注释中写到：「这个补丁展示了 eBPF 的潜力」。当前，eBPF 不再局限于网络栈，已经成为内核顶级的子系统。

**eBPF 与内核模块**

对比 Web 的发展，eBPF 与内核的关系有点类似于 JavaScript 与浏览器内核的关系，eBPF 相比于直接修改内核和编写内核模块提供了一种新的内核可编程的选项。eBPF 程序架构强调安全性和稳定性，看上去更像内核模块，但与内核模块不同，eBPF 程序不需要重新编译内核，并且可以确保 eBPF 程序运行完成，而不会造成系统的崩溃。

| 维度                | Linux 内核模块                       | eBPF                                           |
| ------------------- | ------------------------------------ | ---------------------------------------------- |
| kprobes/tracepoints | 支持                                 | 支持                                           |
| 安全性              | 可能引入安全漏洞或导致内核 Panic     | 通过验证器进行检查，可以保障内核安全           |
| 内核函数            | 可以调用内核函数                     | 只能通过 BPF Helper 函数调用                   |
| 编译性              | 需要编译内核                         | 不需要编译内核，引入头文件即可                 |
| 运行                | 基于相同内核运行                     | 基于稳定 ABI 的 BPF 程序可以编译一次，各处运行 |
| 与应用程序交互      | 打印日志或文件                       | 通过 perf_event 或 map 结构                    |
| 数据结构            | 丰富性                               | 一般丰富                                       |
| 入门门槛            | 高                                   | 低                                             |
| 升级                | 需要卸载和加载，可能导致处理流程中断 | 原子替换升级，不会造成处理流程中断             |
| 内核内置            | 视情况而定                           | 内核内置支持                                   |

**eBPF 架构**

eBPF 分为用户空间程序和内核程序两部分：

- 用户空间程序负责加载 BPF 字节码至内核，如需要也会负责读取内核回传的统计信息或者事件详情
- 内核中的 BPF 字节码负责在内核中执行特定事件，如需要也会将执行的结果通过 maps 或者 perf-event 事件发送至用户空间
- 其中用户空间程序与内核 BPF 字节码程序可以使用 map 结构实现双向通信，这为内核中运行的 BPF 字节码程序提供了更加灵活的控制

eBPF 整体结构图如下：

![img](https://996station.com/wp-content/uploads/2022/11/20221126103924639.png?imageView2/0/format/webp/q/75)

用户空间程序与内核中的 BPF 字节码交互的流程主要如下：

1、使用 LLVM 或者 GCC 工具将编写的 BPF 代码程序编译成 BPF 字节码

2、使用加载程序 Loader 将字节码加载至内核

3、内核使用验证器（Verfier） 组件保证执行字节码的安全性，以避免对内核造成灾难，在确认字节码安全后将其加载对应的内核模块执行

4、内核中运行的 BPF 字节码程序可以使用两种方式将数据回传至用户空间：

- maps 方式可用于将内核中实现的统计摘要信息（比如测量延迟、堆栈信息）等回传至用户空间；
- perf-event 用于将内核采集的事件实时发送至用户空间，用户空间程序实时读取分析。

**eBPF 限制**

eBPF 技术虽然强大，但是为了保证内核的处理安全和及时响应，内核中的 eBPF 技术也给予了诸多限制，当然随着技术的发展和演进，限制也在逐步放宽或者提供了对应的解决方案。

eBPF 程序不能调用任意的内核参数，只限于内核模块中列出的 BPF Helper 函数，函数支持列表也随着内核的演进在不断增加。

eBPF 程序不允许包含无法到达的指令，防止加载无效代码，延迟程序的终止。

eBPF 程序中循环次数限制且必须在有限时间内结束，这主要是用来防止在 kprobes 中插入任意的循环，导致锁住整个系统；解决办法包括展开循环，并为需要循环的常见用途添加辅助函数。Linux 5.3 在 BPF 中包含了对有界循环的支持，它有一个可验证的运行时间上限。

eBPF 堆栈大小被限制在 MAX_BPF_STACK，截止到内核 Linux 5.8 版本，被设置为 512；参见 include/linux/filter.h[3]，这个限制特别是在栈上存储多个字符串缓冲区时：一个char[256]缓冲区会消耗这个栈的一半。目前没有计划增加这个限制，解决方法是改用 bpf 映射存储，它实际上是无限的。

```
/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK 512
```

eBPF 字节码大小最初被限制为 4096 条指令，截止到内核 Linux 5.8 版本， 当前已将放宽至 100 万指令（ BPF_COMPLEXITY_LIMIT_INSNS），参见：include/linux/bpf.h[4]，对于无权限的BPF程序，仍然保留4096条限制 ( BPF_MAXINSNS )；新版本的 eBPF 也支持了多个 eBPF 程序级联调用，虽然传递信息存在某些限制，但是可以通过组合实现更加强大的功能。

```
#define BPF_COMPLEXITY_LIMIT_INSNS      1000000 /* yes. 1M insns */
```

## 

