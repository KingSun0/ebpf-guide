# eBPF解读-基础篇

**1.简介**

> BPF，即Berkeley Packet Filter，是一个古老的网络封包过滤机制。它允许从用户空间注入一段简短的字节码到内核来定制封包处理逻辑。Linux从2.5开始移植了BPF，tcpdump就是基于BPF的应用。

所谓eBPF（extended BPF），则是从3.18引入的，对BPF的改造和功能增强：

1. 使用类似于X86的体系结构，eBPF设计了一个通用的RISC指令集，支持11个64bit寄存器（32bit子寄存器）r0-r10，使用512字节的栈空间
2. 引入了JIT编译，取代了BPF解释器。eBPF程序直接被编译为目标体系结构的机器码
3. 和网络子系统进行了解耦。它的数据模型是通用的，eBPF程序可以挂钩到 Kprobe或Tracepoint
4. 使用Maps来存储全局数据，这是一种通用的键值存储。可用作不同eBPF程序、eBPF和用户空间程序的状态共享
5. 助手函数（Helper Functions），这些函数供eBPF程序调用，可以实现封包改写、Checksum计算、封包克隆等能力
6. 尾调用（Tail Calls），可以用于将程序控制权从一个eBPF转移给另外一个。老版本的eBPF对程序长度有4096字节的限制，通过尾调用可以规避
7. 用于Pin对象（Maps、eBPF程序）的伪文件系统
8. 支持将eBPF Offload给智能硬件的基础设施

以上增强，让eBPF不仅仅限于网络封包处理，当前eBPF的应用领域包括：

1. 网络封包处理：XDP、TC、socket progs、kcm、calico、cilium等
2. 内核跟踪和性能监控：KProbes、UProbes、TracePoints
3. 安全领域：Secomp、landlock等。例如阻止部分类型的系统调用

现在BPF一般都是指eBPF，而老的BPF一般称为cBPF（classic BPF）。

性能是eBPF的另外一个优势，由于所有代码都在内核空间运行，避免了复制数据到用户空间、上下文切换等开销。甚至编译过程都在尽可能的优化，例如助手函数会被内联到eBPF程序中，避免函数调用的开销。

用户提供的代码在内核中运行，安全性需要得到保证。eBPF校验器会对字节码进行各方面的检查，确保它不会导致内核崩溃或锁死。

eBPF具有非常好的灵活性、动态性，可以随时的注入、卸载，不需要重启内核或者中断网络连接。

eBPF程序可以在不同体系结构之间移植。

**2.eBPF基础**

**BPF架构**

![img](https://996station.com/wp-content/uploads/2022/11/20221126095400633.png?imageView2/0/format/webp/q/75)

如上图所示，eBPF应用程序，从开发到运行的典型流程如下：

1. 利用Clang，将C语言开发的代码编译为eBPF object文件
2. 在用户空间将eBPF object文件载入内核。载入前，可能对object文件进行各种修改。这一步骤，可能通过iproute2之类的BPF ELF loader完成，也可能通过自定义的控制程序完成
3. BPF Verifier在VM中进行安全性校验
4. JIT编译器将字节码编译为机器码，返回BPF程序的文件描述符
5. 使用文件描述符将BPF程序挂钩到某个子系统（例如networking）的挂钩点。子系统有可能将BPF程序offload给硬件（例如智能网卡）
6. 用户空间通过eBPF Map和内核空间交换数据，获知eBPF程序的执行结果

**挂钩点**

eBPF程序以事件驱动的方式执行，具体来说，就是在内核的代码路径上，存在大量挂钩点（Hook Point）。eBPF程序会注册到某些挂钩点，当内核运行到挂钩点后，就执行eBPF程序。

挂钩点主要包括以下几类：

1. 网络事件，例如封包到达
2. Kprobes / Uprobes
3. 系统调用
4. 函数的入口/退出点

**BPF Verifier**

在加载之后，BPF校验器负责验证eBPF程序是否安全，它会模拟所有的执行路径，并且：

1. 检查程序控制流，发现循环
2. 检测越界的跳转、不可达指令
3. 跟踪Context的访问、栈移除
4. 检查unpriviledged的指针泄漏
5. 检查助手函数调用参数

**BPF JITs**

在校验之后，eBPF程序被JIT编译器编译为Native代码。

**BPF Maps**

键值对形式的存储，通过文件描述符来定位，值是不透明的Blob（任意数据）。用于跨越多次调用共享数据，或者与用户空间应用程序共享数据。

一个eBPF程序可以直接访问最多64个Map，多个eBPF程序可以共享同一Map。

**Pinning**

BPF Maps和程序都是内核资源，仅能通过文件描述符访问到。文件描述符对应了内核中的匿名inodes。

用户空间程序可以使用大部分基于文件描述符的API，但是文件描述符是限制在进程的生命周期内的，这导致Map难以被共享。比较显著的例子是iproute2，当tc或XDP加载eBPF程序之后，自身会立刻退出。这导致无法从用户空间访问Map。



为了解决上面的问题，引入了一个最小化的、内核空间中的BPF文件系统。BPF程序和Map会被pin到一个被称为object pinning的进程。bpf系统调用有两个命令BPF_OBJ_PIN、BPF_OBJ_GET分别用于钉住、取回对象。

tc这样的工具就是利用Pinning在ingress/egress端共享Map。

**尾调用**

尾调用允许一个BPF程序调用另外一个，这种调用没有函数调用那样的开销。其实现方式是long jump，重用当前stack frame。

注意：只用相同类型的BPF程序才能相互尾调用。

要使用尾调用，需要一个BPF_MAP_TYPE_PROG_ARRAY类型的Map，其内容目前必须由用户空间产生，值是需要被尾调用的BPF程序的文件描述符。通过助手函数bpf_tail_call触发尾调用，内核会将此调用内联到一个特殊的BPF指令。

**BPF-BPF调用**

BPF - BPF调用是一个新添加的特性。在此特性引入之前，典型的BPF C程序需要将所有可重用的代码声明为always_inline的，这样才能确保LLVM生成的object包含所有函数。这会导致函数在每个object文件中都反复（只要它被调用超过一次）出现，增加体积。

```
 
#include <linux/bpf.h>
 
#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif
 
#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif
 
// 总是内联
static __inline int foo(void)
{
    return XDP_DROP;
}
 
__section("prog")
int xdp_drop(struct xdp_md *ctx)
{
    return foo();
}
 
char __license[] __section("license") = "GPL";
```

总是需要内联的原因是BPF的Loader/Verifier/Interpreter/JITs不支持函数调用。但是从内核4.16和LLVM 6.0开始，此限制消除，BPF程序不再总是需要always_inline。上面程序的__inline可以去掉了。

目前x86_64/arm64的JIT编译器支持BPF to BPF调用，这是很重要的性能优化，因为它大大简化了生成的object文件的尺寸，对CPU指令缓存更加友好。



JIT编译器为每个函数生成独立的映像（Image），并且在JIT的最后一个步骤中修复映像中的函数调用地址。

到5.9为止，你不能同时使用BPF-BPF调用（BPF子程序）和尾调用。从5.10开始，可以混合使用，但是仍然存在一些限制。此外，混合使用两者可能导致内核栈溢出，原因是尾调用在跳转之前仅会unwind当前栈帧。

**Offloading**

BPF网络程序，特别是tc和XDP，提供了将BPF代码offload给NIC执行的特性。这个特性需要驱动的支持。

**BPF前端工具**

能够加载BPF程序的前端工具有很多，包括bcc、perf、iproute2等。内核也在tools/lib/bpf目录下提供了用户空间库，被perf用来加载BPF追踪应用程序到内核。这是一个通用的库，你也可以直接调用它。BCC是面向追踪的工具箱。内核在samples/bpf下也提供了一些BPF示例，这些示例解析Object文件，并且直接通过系统调用将其载入内核。

基于不同前端工具，实现BPF程序的语法、语义（例如对于段名的约定）有所不同。

**相关sysctl**

**/proc/sys/net/core/bpf_jit_enable**

启用或禁用BPF JIT编译器：

0 仅用，仅仅使用解释器，默认值
1 启用JIT编译器
2 启用JIT编译器并且生成debugging trace到内核日志

设置为2，可以使用bpf_jit_disasm处理debugging trace

**/proc/sys/net/core/bpf_jit_harden**

启用或禁用JIT加固，加固和性能是对立的，但是可以缓和JIT spraying：

0 禁用JIT加固，默认值
1 对非特权用户启用
2 对所有用户启用

**/proc/sys/net/core/bpf_jit_kallsyms**

启用或禁用JITed的程序的内核符号导出（导出到/proc/kallsyms），这样可以和perf工具一起使用，还能够让内核对BPF程序的地址感知（用于stack unwinding）：

0 启用
1 仅对特权用户启用

**/proc/sys/kernel/unprivileged_bpf_disabled**

是否启用非特权的bpf系统调用。默认启用，一旦禁用，重启前无法恢复启用状态。不会影响seccomp等不使用bpf2系统调用的cBPF程序：

0 启用
1 禁用

**助手函数**

eBPF程序可以调用助手函数，完成各种任务，例如：

1. 在Map中搜索、更新、删除键值对
2. 生成伪随机数
3. 读写隧道元数据
4. 尾调用 —— 将eBPF程序链在一起
5. 执行套接字相关操作，例如绑定、查询Cookies、重定向封包
6. 打印调试信息
7. 获取系统启动到现在的时间

助手函数是定义在内核中的，有一个白名单，决定哪些内核函数可以被eBPF程序调用。

根据eBPF的约定，助手函数的参数数量不超过5。

编译后，助手函数的代码是内联到eBPF程序中的，因而不存在函数调用的开销（栈帧处理开销、CPU流水线预取指令失效开销）。

返回int的类型的助手函数，通常操作成功返回0，否则返回负数。如果不是如此，会特别说明。

助手函数不可以随意调用，不同类型的eBPF程序，可以调用不同的助手函数子集。

**3.iproute2**

iproute2提供的BPF前端，主要用来载入BPF网络程序，这些程序的类型包括XDP、tc、lwt。只要是为iproute2编写的BPF程序，共享统一的加载逻辑。

**XDP**

**加载XDP程序**

编译好的XDP类型（BPF_PROG_TYPE_XDP）的BPF程序 ，可以使用如下命令载入到支持XDP的网络设备：

ip link set dev eth0 xdp obj prog.o

 上述命令假设程序位于名为prog的段中。如果不使用默认段名，则需要指定sec参数：

\# 如果程序放在foobar段
ip link set dev em1 xdp obj prog.o sec foobar

如果程序没有标注段，也就是位于默认的.text段，则也可以用上面的命令加载。

如果已经存在挂钩到网络设备的XDP程序，默认情况下命令会报错，可以用-force参数强制替换：

ip -force link set dev em1 xdp obj prog.o

大多数支持XDP的驱动，能够原子的替换XDP程序，而不会引起流量中断。出于性能的考虑同时只能有一个XDP程序挂钩， 可以利用前文提到的尾调用来组织多个XDP程序。

如果网络设备挂钩了XDP程序，则ip link命令会显示xdp标记和程序的ID。使用bpftool传入ID可以查看更多细节信息。

**卸载XDP程序**

ip link set dev eth0 xdp off

**XDP操作模式**

iproute2实现了XDP所支持的三种操作模式：

1. xdpdrv：即native XDP，BPF程序在驱动的接收路径的最早时刻被调用。这是正常的XDP模式，上游内核的所有主要10G/40G+网络驱动（包括virtio）都实现了XDP支持，也就是可使用该模式
2. xdpoffload：由智能网卡的驱动（例如Netronome的nfp驱动）实现，将整个XDP程序offload到硬件中，网卡每接收到封包都会执行XDP程序。该模式比native XDP的性能更高，缺点是，并非所有助手函数、Map类型可用。
3. xdpgeneric：即generic XDP，作为尚不支持native XDP的驱动的试验台。挂钩点比native XDP晚很多，已经进入网络栈的主接收路径，生成了skb对象，因此性能比native XDP差很多，不会用于生产环境

在切换驱动的XDP模式时，驱动通常需要重新配置它的接收/发送Rings，以保证接收到的封包线性的（linearly）存放到单个内存页中。

调用ip link set dev xxx xdp命令时，内核会首先尝试在native XDP模式下载入，如果驱动不支持，则自动使用generic XDP模式。要强制使用native XDP，则可以使用：



\# 强制使用native XDP
ip -force link set dev eth0 xdpdrv obj prog.o

使用类似的方式可以强制使用xdpgeneric、xdpoffload。

切换操作模式目前不能原子的进行，但是在单个操作模式下替换XDP程序则可以。

使用 verb选项，可以显示详尽的BPF校验日志：

ip link set dev eth0 xdp obj xdp-example.o verb

除了从文件加载BPF程序，也可以直接从BPF伪文件系统中得到程序并使用：

ip link set dev eth0 xdp pinned /sys/fs/bpf/prog
\# m:表示BPF文件系统的挂载点，默认/sys/fs/bpf/
ip link set dev eth0 xdp pinned m:prog

 **tc**

对于为tc设计的BPF程序（BPF_PROG_TYPE_SCHED_CLS、BPF_PROG_TYPE_SCHED_ACT），可以使用tc命令加载并挂钩到网络设备。和XDP不同，tc程序没有对驱动的依赖。

clsact是4.1引入了一个特殊的dummy qdisc，它持有classifier和action，但是不能执行实际的queueing。要挂钩BPF classifier，clsact是必须启用的：

```
$ tc qdisc add dev eth0 clsact
```

clsact提供了两个特殊的钩子 ingress、 egress，对应了BPF classifier可用的两个挂钩点。这两个钩子位于网络数据路径的中心位置，任何封包都必须经过

下面的命令，将BPF程序挂钩到eth0的ingress路径上：

```
$ tc filter add dev eth0 ingress bpf da obj prog.o
```

下面的命令将BPF程序挂钩到eth0的egress路径上：

```
$ tc filter add dev eth0 egress bpf da obj prog.o
```

ingress钩子在内核中由 __netif_receive_skb_core() -> sch_handle_ingress()调用。

egress钩子在内核中由 __dev_queue_xmit() -> sch_handle_egress()调用。

clsact是以无锁方式处理的，支持挂钩到虚拟的、没有队列概念的网络设备，例如veth。

da即direct-action模式，这是推荐的模式，应当总是在命令中指定。da模式表示BPF classifier不需要调用外部的tc action模块，因为BPF程序会将封包修改、转发或者其它动作都完成，这正是BPF性能优势所在。

类似XDP，如果不使用默认的段名，需要用sec选项：

```
$ tc filter add dev eth0 egress bpf da obj prog.o sec foobar
```

已经挂钩到设备的tc程序的列表，可以用下面的命令查看：

```
 
tc filter show dev em1 ingress
filter protocol all pref 49152 bpf
 
     # 针对的L3协议    优先级      分类器类型  分类器句柄
filter protocol all    pref 49152 bpf        handle 0x1 
  # 从prog.o的ingress段加载了程序
  prog.o:[ingress] 
  # BPF程序运行在da模式
  direct-action 
  # 程序ID是全局范围唯一的BPF程序标识符，可以被bpftool使用
  id 1 
  # 程序指令流的哈希，哈希可以用来关联到Object文件，perf报告栈追踪的时候使用此哈希
  tag c5f7825e5dac396f
 
 
tc filter show dev em1 egress
filter protocol all pref 49152 bpf
filter protocol all pref 49152 bpf handle 0x1 prog.o:[egress] direct-action id 2 tag b2fd5adc0f262714
```

tc可以挂钩多个BPF程序，这和XDP不同，它提供了多个其它的、可以链接在一起的classifier。尽管如此，单个da模式的BPF程序可以满足所有封包操作需求，它可以直接返回action断言，例如 TC_ACT_OK, TC_ACT_SHOT。使用单个BPF程序是推荐的用法。

除非打算自动替换挂钩的BPF程序，建议初次挂钩时明确的指定pref和handle，这样，在后续手工替换的时候就不需要查询获取pref、handle：

```
$ tc filter add dev eth0 ingress pref 1 handle 1 bpf da obj prog.o sec foobar
```

使用下面的命令原子的替换BPF程序：

```
$ tc filter replace dev eth0 ingress pref 1 handle 1 bpf da obj prog.o sec foobar
```

要移除所有以及挂钩的BPF程序，执行：

```
$ tc filter del dev eth0 ingress
$ tc filter del dev eth0 egress
```

要从网络设备上移除整个clsact qdisc，可以：

```
$ tc qdisc del dev eth0 clsact
```

类似于XDP程序，tc程序也支持offload给职能网卡。你需要首先启用hw-tc-offload：

```
$ ethtool -K eth0 hw-tc-offload on
```

然后再启用clsact并挂钩BPF程序。XDP和tc的offloading不能同时开启。

 **netdevsim**

内核提供了一个dummy驱动netdevsim，它实现了XDP/tc BPF的offloading接口，用于测试目的。

下面的命令可以启用netdevsim设备：

```
modprobe netdevsim
echo "1 1" > /sys/bus/netdevsim/new_device
devlink dev
# netdevsim/netdevsim1
devlink port
# netdevsim/netdevsim1/0: type eth netdev eth0 flavour physical
ip l
# 4: eth0:mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
#  link/ether 2a:d5:cd:08:d1:3f brd ff:ff:ff:ff:ff:ff
```

**4.XDP**

**简介**

在网络封包处理方面，出现过一种提升性能的技术 —— 内核旁路（Kernel Bypass ）：完全在用户空间实现网络驱动和整个网络栈，避免上下文切换、内核网络层次、中断处理。具体实现包括Intel的DPDK （Data Plane Development Kit）、Cisco的VPP等。

内核旁路技术的缺点是：

1. 作为硬件资源的抽象层，内核是经过良好测试和验证的。在用户空间重新实现驱动，稳定性、可复用性欠佳
2. 实现网络栈也是困难的
3. 作为一个沙盒，网络处理程序难以和内核其它部分集成/交互
4. 无法使用内核提供的安全层

eXpress Data Path，为内核提供了一个基于eBPF的、高性能的、可编程的、运行在驱动层的封包处理框架，它提升性能的思路和内核旁路技术相反 —— 完全在内核空间实现封包处理逻辑，例如过滤、映射、路由等。XDP通过在网络接收路径的最早期挂钩eBPF程序来实现高速封包过滤。最早期意味着：NIC驱动刚刚从receiver rings接收到封包，任何高成本操作，例如分配skb并将封包推入网络栈，尚未进行。

XDP的起源来自于对DDoS攻击的防范。Cloudflare依赖（leverages heavily on）iptables进行封包过滤，在配置相当好的服务器上，可以处理1Mpps的流量。但是当出现DDoS攻击时，流量会高达3Mpps，这会导致Linux系统overflooded by IRQ请求，直到系统变得不稳定。



由于Cloudflare希望继续使用iptables以及其它内核网络栈功能，它不考虑使用DPDK这样的完全控制硬件的方案，而是使用了所谓部分内核旁路（partial kernel bypass），NIC的一部分队列继续附到内核，另外一部分队列则附到一个用户空间应用程序，此程序决定封包是否应该被丢弃。通过在网络栈的最底部就决定是否应该丢弃封包，需要经由内核网络子系统的封包数量大大减少了。

Cloudflare利用了Netmap工具包实现部分内核旁路。但是这个思路可以延伸为，在内核网络栈中增加一个Checkpoint，这个点应该离NIC接收到封包的时刻尽可能的近。这个Checkpoint将把封包交给用户编写的程序，决定是应该丢弃，还是继续正常处理路径。

![img](https://996station.com/wp-content/uploads/2022/11/20221126095135113.png?imageView2/0/format/webp/q/75)

XDP对应的BPF程序类型是：BPF_PROG_TYPE_XDP。XDP程序可以读写封包，调用助手函数解析封包、计算Checksum，这些操作都不会牵涉系统调用的开销（都在内核空间执行）。

尽管XDP的基本用途是，尽早的决定封包是否应该丢弃。但是，由于网络函数无非是读、写、转发、丢弃等原语的组合，XDP可以用来实现任何网络功能。

XDP的主要优势包括：

1. 可以使用各种内核基础设施，例如路由表、套接字、网络栈
2. 运行在内核中，使用和内核其它部分一致的安全模型
3. 运行在内核中，不需要跨越用户/内核空间边界，能够灵活的转发封包给其它内核实体，例如命名空间、网络栈
4. 支持动态替换XDP程序，不会引起网络中断
5. 保证封包的线性（linearly）布局，封包位于单个DMAed内存页中，访问起来很方便
6. 保证封包有256字节可用的额外headroom，可以用于（使用助手函数 bpf_xdp_adjust_head、 bpf_xdp_adjust_meta）添加自定义的封装包头

从内核4.8+开始，主要发行版中XDP可用，大部分10G+网络驱动支持XDP。

**应用场景**

**DDoS缓解**

XDP的高性能特征，让它非常适合实现DDoS攻击缓解，以及一般性防火墙。

**封包转发**

BPF程序可以对封包进行任意的修改，甚至是通过助手函数任意的增减headroom大小实现封装/解封装。

处理完的封包通过XDP_REDIRECT动作即可转发封包给其它NIC，或者转发给其它CPU（利用BPF的cpumap）

**负载均衡**

使用XDP_TX动作，hairpinned LB可以将修改后的封包从接收它的网卡发送回去。

**流量采样和监控**

XDP支持将部分或截断的封包内容存放到无锁的per-CPU的内存映射ring buffer中。此ring buffer由Linux perf基础设施提供，可以被用户空间访问。

**编程接口**

xdp_buff

在XDP中，代表当前封包的结构是：

```
struct xdp_buff {
    // 内存页中，封包数据的开始点指针
    void *data;
    // 内存页中，封包数据的结束点指针
    void *data_end;
    // 最初和和data指向同一位置。后续可以被bpf_xdp_adjust_meta()调整，向data_hard_start方向移动
    // 可以用于为元数据提供空间。这种元数据对于正常的内核网络栈是不可见的，但是能够被tc BPF程序读取，
    // 因为元数据会从XDP传送到skb中
    // data_meta可以仅仅适用于在尾调用之间传递信息，类似于可被tc访问的skb->cb[]
    void *data_meta;
    // XDP支持headroom，这个字段给出页中，此封包可以使用的，最小的地址
    // 如果封包被封装，则需要调用bpf_xdp_adjust_head()，将data向data_hard_start方向移动
    // 解封装时，也可以使用bpf_xdp_adjust_head()移动指针
    void *data_hard_start;
    // 提供一些额外的per receive queue元数据，这些元数据在ring setup time生成
    struct xdp_rxq_info *rxq;
};
 
// 接收队列信息
struct xdp_rxq_info {
    struct net_device *dev;
    u32 queue_index;
    u32 reg_state;
} ____cacheline_aligned; // 缓存线（默认一般是64KB），CPU以缓存线为单位读取内存到CPU高速缓存
它通过BPF context传递给XDP程序。
xdp_action
enum xdp_action {
    // 提示BPF出现错误，和DROP的区别仅仅是会发送一个trace_xdp_exception追踪点
    XDP_ABORTED = 0,
    // 应当在驱动层丢弃封包，不必再浪费额外资源。对于DDos缓和、一般性防火墙很有用
    XDP_DROP,
    // 允许封包通过，进入网络栈进行常规处理
    // 处理此封包的CPU后续将分配skb，将封包信息填充进去，然后传递给GRO引擎
    XDP_PASS,
    // 将封包从接收到的网络接口发送回去，可用于实现hairpinned LB
    XDP_TX,
    // 重定向封包给另外一个NIC
    XDP_REDIRECT,
};
```

这个枚举是XDP程序需要返回的断言，告知驱动应该如何处理封包。

## 作者

CMIT云原生

## 原文链接

https://mp.weixin.qq.com/s/JLHg14ZUpZzGHWaY_o455w