# BPF(eBPF)最初是来源于网络流量过滤的需求

一般我们会听到类似这样的说法：BPF/eBPF 最初是来源于网络流量过滤的需求，但它现在已被扩展到一般的内核观测中。那就先来看看，它为何是产生自网络传输领域的。

### **怎样快速过滤**

现代网络传输有个特点：流量巨大，因此需要快速过滤。那如何才能快速？比如这样一个过滤器：

![img](https://996station.com/wp-content/uploads/2022/11/20221126102459310.png?imageView2/0/format/webp/q/75)

如果采用基于传统的 tree 的结构来实现，大致是这样的：

![img](https://996station.com/wp-content/uploads/2022/11/20221126102508782.png?imageView2/0/format/webp/q/75)

假设被过滤的 packet 是一个 ARP 包或者 IP 包，那么通过这样一种树形结构来判断是很快的，但如果既不是 ARP 也不是 IP 包呢（也就是 P1 和 P2 这两个条件都为 false），那么 AND1 和 AND2 就是没必要的。

而 BPF 采用基于 CFG (Control Flow Graph) 的结构实现：

![img](https://996station.com/wp-content/uploads/2022/11/20221126102517283.png?imageView2/0/format/webp/q/75)

判断从顶点的 P1 开始，当条件为 false 时走右路，true 时走左路，直到抵达末端的 false 或者 true。这样，当 P1 和 P2 都为 false 时，就可以直达最后的 false，而不需要再判断 P3 和 P4。

好，接下来再来看看它是如何被应用到内核行为的观测中的。

### **过滤的输入 - 前端**

观测需要数据，准确的说是你感兴趣的那些数据，那它们来自哪里？内核依靠执行一条条的指令运行，所以可以在执行指令的点位抓取数据。

说到如何抓取，不管是静态的的 tracepoint 和 ftrace，还是动态的 kprobe，都可以被视作提供了 event source 的一种 hook 行为，而 perf, systemtap 等工具都依赖于这些作为数据输入的「前端」，在 kernel tracing 中发挥作用的 BPF/eBPF 也不例外。

### **过滤的输出 - 后端**

需要劫持哪些 hook 点，劫持后需要获取哪些数据，以及之后怎样处理这些数据，就是所谓「后端」做的事了。具体而言，比较简便快速的方法是在用户态编写 perf, systemtap 等对应的脚本来指定。

在这一点上，BPF/eBPF 可以说和前两者并没有本质上的区别，它支持用 bpftrace （融合了 awk 和 C 的语法）或者 python （比如 bcc-tools）等语言来编写脚本，然后经过 LLVM 的处理，转化为可以在机器上执行的代码。

### **为什么需要虚拟机**

只不过，针对 BPF/eBPF，是先转换为面向 BPF 虚拟机的 bytecode。为啥需要一个 VM 呢？其中一个原因是前面说到的 BPF 采用的 CFG 结构，这种结构很适合用 bytecode 的形式来表达。

既然是 VM，通常就有自己的一套指令集 (ISA) 和寄存器，且由于最终运行在内核，所以应尽量保持和 Linux 的 calling convention 的兼容，这就要求其功能设计上应尽量保持和真实 CPU 在寄存器/指令集上的接近。



诞生于上世纪 90 年代初的 BPF 只有 2 个 寄存器，随着 CPU 技术的不断迭代，寄存器已普遍步入了 64 位时代，且产生了一些专门面向多核处理器的新指令。正是由于 BPF 虚拟机和底层 CPU 存在的这种关联，这种寄存器和指令都非常有限的设计，已越来越不能利用现代处理器发展带来的红利。

这也是 20 年后的 eBPF 选择在这方面进行扩展的原因，其中就寄存器这一块，已经被扩展到了 10 个（包括 R0 到 R9，未将作为只读 frame pointer 的 R10 涵盖在内），基本可以形成和硬件寄存器一对一的映射关系，以 x86-64 体系为例，其对应关系如下：

![img](https://996station.com/wp-content/uploads/2022/11/20221126102526928.png?imageView2/0/format/webp/q/75)

经过 eBPF 的改良，多种网络过滤的 benchmark 的结果显示（以 3.15 内核为例），其相较 BPF 在性能有了 1.5 到 4 倍的提升。

不过其目前在使用上还是存在一些限制的，比如函数参数不能超过 5 个，只允许 1 个返回值（因为只有 rax 作为存放 return value 的寄存器）等。



既然是 VM，那么 bytecode 还需要转为主机上真实硬件架构（比如 x86）的汇编指令，这里就要用到 JIT 来作为解释器。下图的蓝色箭头部分就展示了上述的这一过程，即 eBPF 中作为 filter 的程序是如何流转和工作的。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102533147.png?imageView2/0/format/webp/q/75)

内核通过探测点获得了数据后，又该如何传递给用户态呢？答案是存储在 eBPF maps 中。这些 maps 采用 key/value 的形式（比如组织为 hash 表），因而可以包含不同类型的数据，这也是 "eBPF" 里这个 "e" 所代表的 extended 的一个体现。

上图的红色箭头部分，呈现的正是 eBPF maps 作为用户态和内核态共享数据的方式（当然它也可以作为 eBPF 的内核态程序之间进行数据交互的渠道）。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102539348.png?imageView2/0/format/webp/q/75)

这里就要说到 eBPF 的一个优势了。相比于 perf 需要将采集数据存储在 buffer 里，然后传送到用户态解析的方式不同，eBPF 支持在内核态直接处理一些数据（比如生成直方图），这可以减少用户态和内核态的数据拷贝，有利于降低观测工具带来的开销，因而更适合作为生产环境的 performance tool【注-1】。

![img](https://996station.com/wp-content/uploads/2022/11/20221126102545474.png?imageView2/0/format/webp/q/75)

其适用于生产环境的另一个重要原因是它的安全性。VM 为 eBPF 程序的运行提供了一个类似 sandbox 的环境，是保障其不会造成内核 crash 的基石之一，但如果希望 eBPF 像 systemtap 那样，可以通过修改函数的返回值来实现 fault injection 的功能，那么很可能就会破坏这一层保障，这也算是 production safe 对 eBPF 适用面扩展的一个掣肘吧。

注-1：自 eBPF 出现后，BPF 已被替代，所以目前说到 "BPF"，有时就是指 "eBPF"。

## 作者

术道经纬

## 原文链接

https://mp.weixin.qq.com/s/udpHAaB27DpVPm1ynvUxuA