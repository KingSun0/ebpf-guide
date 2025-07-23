# eBPF允许您在内核中编写自定义代码

eBPF 非常强大，因为它在所有魔法发生的地方（Linux 内核）根深蒂固。eBPF 允许您在内核中编写自定义代码。

![img](https://996station.com/wp-content/uploads/2022/11/20221126085012594.png?imageView2/0/format/webp/q/75)

## 什么是 eBPF？

> eBPF（不再是任何东西的缩写）是一项革命性的技术，起源于 Linux 内核，可以在操作系统内核等特权上下文中运行沙盒程序。它用于安全有效地扩展内核的功能，而无需更改内核源代码或加载内核模块。

## eBPF 是如何工作的？

> eBPF 程序是事件驱动的，当内核或应用程序通过某个挂钩点时运行。预定义的挂钩包括系统调用、函数入口/出口、内核跟踪点、网络事件等。

[![eBPF 概述由 eBPF.io 提供](https://shortcdn.com/devopsish/ebpf-overview.webp)](https://ebpf.io/)

eBPF 概述由[eBPF.io](https://ebpf.io/)根据[Creative Commons Attribution 4.0 International License 提供](https://creativecommons.org/licenses/by/4.0/)。

关于 eBPF，您应该立即为两个站点添加书签：

- [https://ebpf.foundation/（Linux](https://ebpf.foundation/)基金会网站）
- [https://ebpf.io](https://ebpf.io/)（由 Daniel Borkmann 运营）

在撰写本文时，这两个网站看起来惊人地相似，但运营它们的人却不同。出于“原因”，该`.foundation`网站决定从该`.io`网站的一个分支开始。是的，我知道有几个 SEO 正在读这篇文章，他们刚刚吐了他们选择的饮料。冷静一下。您的设备可能是防水的¯\_(ツ)_/¯。

如果您不熟悉[Isovalent](https://isovalent.com/)，它是制作企业级[Cilium](https://cilium.io/)产品（Cilium 容器网络接口 (CNI)）的人，我的同事[Liz Rice](https://twitter.com/lizrice)和[Duffie Cooley](https://twitter.com/mauilion)就在这里工作。如果您还记得的话，我今年早些时候与他们坐下[来聊了聊他们在 KubeCon EU 2022 之前的计划](https://chrisshort.net/video/aws-container-days-eu-2022-day-3/#cilium-on-eks-anywhere--liz-rice-chief-open-source-officer-isovalent---duffie-cooley-field-cto-isovalent)。Isovalent 网站上的标语是“基于 eBPF 的网络、安全性和可观察性”。您可以使用 eBPF 做很多艰苦的工作。



如果您像我一样，在添加和删除模块以优化系统或使独特的硬件工作之前一直深入了解内核，您就会知道这通常会非常具有破坏性或破坏性。eBPF 使您能够以新的和令人兴奋的方式处理内核，而无需运行单个`modprobe`命令甚至重新启动。它们通常也比内核模块更安全。[为了保证eBPF 的安全](https://ebpf.io/what-is-ebpf/#ebpf-safety)，我们付出了很多努力。

您编写的 eBPF 程序会触发 Linux 内核中的不同事件，或者完全阻止它们发生。因此，eBPF 非常强大，因为它在所有魔法发生的地方（Linux 内核）根深蒂固。eBPF 允许您在内核中编写自定义代码。由于活动发生在内核中，它通常使 eBPF 程序快速高效。例如，您编写的程序甚至可以在访问网络堆栈之前拦截网络访问，或者提供有关由哪些程序进行的调用的详细执行信息以实现可观察性。



这是很多人的学习路径出现分歧的地方。有些人会想阅读所有的东西。好消息是[BPF 和 XDP 参考指南](https://docs.cilium.io/en/latest/bpf/)以及[HOWTO 与 BPF 子系统的交互](https://www.kernel.org/doc/html/latest/bpf/bpf_devel_QA.html)是*非常棒*的深入研究。其他人希望看到一些实现。如果您想挑选，请查看[awesome-ebpf 存储](https://github.com/zoidbergwill/awesome-ebpf)库。想看一些实现吗？首先，我推荐观看[Liz Rice 在 GOTO 2021 上使用 Go 进行 eBPF 编程的初学者指南](https://youtu.be/uBqRv8bDroc)。另外，[eBPF 到底是什么，为什么 Kubernetes 管理员应该关心？](https://www.groundcover.com/blog/what-is-ebpf)如果您在 Kubernetes 上使用 eBPF，这是一个很好的参考。

## eBPF 程序

什么样的程序可以利用 eBPF？实际上有很多：

- [pixie](https://github.com/pixie-io/pixie) : Instant Kubernetes-Native Application Observability (aka FM: F'ing Magic)
- [boopkit](https://github.com/kris-nova/boopkit)：基于 TCP 的 Linux eBPF 后门。在先前的特权访问上生成反向 shell，RCE。少本金，多东京。
- [Calico](https://projectcalico.docs.tigera.io/about/about-calico)：一个开源网络和网络安全解决方案，适用于容器、虚拟机和基于主机的本地工作负载（他们的[eBPF 页面有漂亮的图片](https://projectcalico.docs.tigera.io/about/about-ebpf)）
- [kubectl trace](https://github.com/iovisor/kubectl-trace)：kubectl 插件，允许您在 Kubernetes 集群中安排 bpftrace 程序的执行
- [bpftrace](https://bpftrace.org/)：Linux 系统的高级跟踪语言
- [Falco](https://falco.org/blog/choosing-a-driver/#ebpf-probe)：Falco eBPF 探针在内核模块不受信任或不允许但 eBPF 程序可用的环境中是一个可行的选择
- [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux) : Sysmon For Linux 是 Windows Sysmon 工具的一个端口，驱动程序被 eBPF 程序替换
- [tracee](https://github.com/aquasecurity/tracee) : 使用 eBPF 的 Linux 运行时安全和取证
- [ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows)：在 Windows 之上运行的 eBPF 实现
- [Katran](https://engineering.fb.com/2018/05/22/open-source/open-sourcing-katran-a-scalable-network-load-balancer/)：Facebook 创建的网络负载均衡器

[eBPF Project Landscape](https://ebpf.io/projects)中还有一个可爱的项目列表。

## eBPF 值得炒作吗？

是的！eBPF 是个好东西，只会随着采用率的提高而改进。我正在等待合适的项目推出上述程序之一，以深入研究性能问题或查看传递给内核的[系统调用。](https://syscall.sh/)

“任何足够先进的技术都与魔法没有区别”适用于此。但是，eBPF 是一个橡皮锤，你不能用它来解决所有问题。你可以用 eBPF 掩盖很多错误。你可以用它找到附近的任何东西，这是任何人都可以给你的最好的开始。



如果您想为 eBPF 或 eBPF 开发工具链做出贡献，请随时在[ebpf.io/contribute](https://ebpf.io/contribute)开始您的旅程。感谢 Alexei Starovoitov、Daniel Borkmann 和整个 eBPF 社区创造了如此出色的技术。

## 作者

克里斯·肖特

## 原文链接

https://chrisshort.net/intro-to-ebpf/