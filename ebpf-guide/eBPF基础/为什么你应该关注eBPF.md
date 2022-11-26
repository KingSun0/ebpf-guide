# 为什么你应该关注eBPF

[KingSun](https://www.996station.com/author/kingsun) 4小时 前



虽然它远非主流主题，但我们已经从我们关注的聪明人那里听到了大量关于 eBPF 的讨论。在 RedMonk，当新兴技术引起我们尊重的人的兴趣时，我们学会了注意，因为从历史上看，这种模式往往表明相关性并暗示未来重要性的潜力。事实上，在这种情况下，所讨论的技术与 DTrace 相关的事实只会给我们带来更多的风险。

这是一个快速的、不全面的 eBPF 入门读物，适合好奇的人：

- eBPF[代表什么](https://ebpf.io/what-is-ebpf/)。它曾经是 Extended Berkeley Packet Filter 的首字母缩写词，但根据文档，它“不再是任何东西的首字母缩写词”。
- eBPF 允许您在 Linux 内核中运行事件驱动程序。程序员可以在沙盒内核环境中运行自定义字节码，而无需直接修改内核源代码本身。
- eBPF 被认为比 Linux 可加载内核模块 (LKM) 更安全，因为在代码执行之前必须通过额外的安全检查和验证。
- 事件可以由各种内核挂钩驱动。触发 eBPF 程序的常见内核挂钩包括系统调用、网络事件（如网络包到达）、对内核中特定函数的调用以及被命中的跟踪点。
- 人们通常不会手写字节码，通常它是从 C 或 Rust 编译而来的。eBPF 程序在被触发后被 JIT 编译为机器码。
- eBPF[与 DTrace 相关](https://www.infoq.com/articles/gentle-linux-ebpf-introduction/)。

*更正*：这篇文章之前说 eBPF 受到 DTrace 的启发，但 Brendan Gregg 在我发表后友善地提供了以下更正。非常感谢他的评论，我在这里分享这些评论是为了向其他人提供此背景信息：

> eBPF 并没有受到 DTrace 的启发；它起源于软件定义网络（在此之前，BPF 本身是用于数据包过滤的）。早期 eBPF 的共同创建者（Alexei Starovoitov，然后在 SDN 初创公司 PLUMgrid 工作）意识到它不仅可以用于实现 SDN，而且我参与使用 eBPF 重新实现我的 DTrace 工具。我们确实有一个名为 bpftrace 的受 DTrace 启发的前端，但那是几年后才出现的。换句话说，DTrace 可以作为一个 eBPF 程序来实现，但 eBPF 本身要大得多。eBPF 不是跟踪器——它是内核执行环境。

- eBPF 的主要用例分为三个总体类别：网络、可观察性和安全性。

eBPF 绝对是一项我们将继续密切关注的技术。特别是随着[Istio Ambient Mesh](https://istio.io/latest/blog/2022/introducing-ambient-mesh/)等技术的引入，eBPF 有望在生态系统中扮演越来越重要的角色。

![img](https://996station.com/wp-content/uploads/2022/11/20221126083840411.png?imageView2/0/format/webp/q/75)

## 其他资源：

- Corey Quinn 对[Liz Rice 进行了精彩的采访，](https://share.transistor.fm/s/cba9541b)讨论了 eBPF 和 Cilium
- [eBPF 文档](https://ebpf.io/what-is-ebpf/)
- 来自 Tigera 的指南：[eBPF 解释](https://www.tigera.io/learn/guides/ebpf/)
- InfoQ：[对 eBPF 的简要介绍](https://www.infoq.com/articles/gentle-linux-ebpf-introduction/)
- [Brendan Gregg 的推文](https://twitter.com/brendangregg)，通常充满了 eBPF 优点

## 作者

Rachel Stephens

## 原文链接

<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" title="“Why You Should Pay Attention to eBPF” — Alt + E S V" src="https://redmonk.com/rstephens/2022/09/08/ebpf/embed/#?secret=9GPWy113bn#?secret=As8LiEOzD0" data-secret="As8LiEOzD0" width="500" height="282" frameborder="0" marginwidth="0" marginheight="0" scrolling="no" style="box-sizing: border-box; max-width: 100%; border: 0px;"></iframe>