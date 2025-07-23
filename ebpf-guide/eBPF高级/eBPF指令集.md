# eBPF指令集

并不是每个开发 BPF 程序的人都知道存在多个版本的指令集。鉴于有关该主题的文档很少，这并不奇怪。那么让我们来看看不同的 eBPF 指令集，它们存在的原因，以及它们的选择为何重要。

### LLVM 的后端选择器

如果你一直使用`llc`它来编译你的 BPF 程序，你可能已经注意到一个`-mcpu`参数。帮助输出为我们提供了以下信息：

```
$ llc -march=bpf -mcpu=help
Available CPUs for this target:
 
  generic - Select the generic processor.
  probe   - Select the probe processor.
  v1      - Select the v1 processor.
  v2      - Select the v2 processor.
  v3      - Select the v3 processor.
 
Available features for this target:
 
  alu32    - Enable ALU32 instructions.
  dummy    - unused feature.
  dwarfris - Disable MCAsmInfo DwarfUsesRelocationsAcrossSections.
 
Use +feature to enable a feature, or -feature to disable it.
For example, llc -mcpu=mycpu -mattr=+feature1,-feature2
```

参数使用`-mcpu`如下：

```
$ clang -O2 -Wall -target bpf -emit-llvm -c example.c -o example.bc
$ llc example.bc -march=bpf -mcpu=probe -filetype=obj -o example.o
```

该参数允许我们告诉 LLVM 使用哪个 eBPF 指令集。它默认为，最旧指令集 `generic`的别名。将选择您的内核支持的最新指令集。我们将在下面看到，选择较新的版本可以让 LLVM 生成更小、更高效的字节码。`v1``probe`

### 先决条件

基本指令集的两个扩展（v2 和 v3）添加了对新跳转指令的支持。具体来说，v2 添加了对低于跳跃的支持，而以前只有大于跳跃可用。当然，第一种跳转可以重写为第二种，但这需要额外的寄存器加载：

```
// Using mcpu=v1:
0: r2 = 7
1: if r2 s> r1 goto pc+1
// Using mcpu=v2's BPF_JSLT:
0: if r1 s< 7 goto pc+1
```

第二个扩展 v3 添加了现有条件 64 位跳转的 32 位变体。同样，您可以通过清除 32 个最高有效位来解决缺少 32 位条件跳转的问题。但是使用 32 位条件跳转更短：

```
0: call bpf_skb_load_bytes
// Using mcpu=v2's 64-bit jumps:
1: r0 <<= 32
2: r0 s>>= 32
3: if r0 s< 0 goto +1785 <LBB10_90>
// Using mcpu=v3's 32-bit jumps:
1: if w0 s< 0 goto +1689 <LBB10_90>
```

`w0`是 的 32 位子寄存器`r0`。

您需要足够新的 Linux 和 LLVM 版本才能使用 v2 和 v3 扩展。下表对其进行了总结。

| BPF ISA version | New instructions             | Linux version                                                | LLVM version                                                 |
| --------------- | ---------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| v1 (generic)    | -                            | [v3.18](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=daedfb22451dd02b35c0549566cbb7cc06bdd53b) | [v3.7](https://reviews.llvm.org/rL227008)                    |
| v2              | `BPF_J{LT,LE,SLT,SLE}`       | [v4.14](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=92b31a9af73b3a3fc801899335d6c47966351830) | [v6.0](https://reviews.llvm.org/rL311522)                    |
| `mattr=+alu32`  | 32-bit calling convention    | [v5.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2dc6b100f928aac8d7532bf7112d3f8d3f952bad)[1](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fn:alu32-support) | [v7.0](https://reviews.llvm.org/rL325983)                    |
| v3              | 32-bit variants of all jumps | [v5.1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=092ed0968bb648cd18e8a0430cd0a8a71727315c) | [v9.0](https://reviews.llvm.org/rL353384), with `mattr=+alu32` |

[BPF 常见问题解答](https://github.com/torvalds/linux/blob/28806e4d9b97865b450d72156e9ad229f2067f0b/Documentation/bpf/bpf_design_QA.rst#q-why-bpf-jlt-and-bpf-jle-instructions-were-not-introduced-in-the-beginning)还很好地了解了为什么存在这些指令集扩展：

> **为什么一开始没有引入BPF_JLT和BPF_JLE指令？**
>
> 答：因为经典 BPF 没有它们，BPF 作者认为编译器变通方案是可以接受的。结果是程序由于缺少这些比较指令而失去了性能，并且添加了它们。这两条指令是新的 BPF 指令的完美示例，可以接受并且可以在将来添加。这两个在本机 CPU 中已经有了等效的指令。不接受与硬件指令没有一对一映射的新指令。

### 对程序大小和复杂性的影响

为什么这一切很重要？使用默认的 v1 指令集有那么糟糕吗？我们可以设置`mcpu=probe`吗？

让我们首先看一下对程序大小的影响。为此，我们可以使用[Cilium 的 BPF 程序](https://github.com/cilium/cilium/tree/master/bpf)。它们是开源的，大小不一，用于生产系统。`check-complexity.sh`Cilium 存储库中的脚本加载内核中的程序并检索各种统计信息。在下文中，我使用的是 LLVM 10.0.0。

```
$ git checkout v1.10.0-rc0
$ for v in v1 v2 v3 "v1 -mattr=+alu32" "v2 -mattr=+alu32"; do \
        sed -i "s/mcpu=v[1-3].*/mcpu=$v/" bpf/Makefile.bpf && \
        make -C bpf KERNEL=netnext &&                         \
        sudo ./test/bpf/check-complexity.sh > ${v/ /-}.txt;   \
done
```

![img](https://996station.com/wp-content/uploads/2022/11/20221126091401390.png?imageView2/0/format/webp/q/75)



正如预期的那样，每个更新的指令集版本都会生成更小的 BPF 程序。由于新指令具有与 x86 指令的一对一映射，我们可以预期对 JIT 编译程序的大小有类似的影响。因此，在大多数情况下，使用较新的指令集时，您可以期望获得较小的性能优势。

的影响`mattr=+alu32`更为细微——单击图例以显示它。它有时会增加程序大小，尤其是与 结合使用时`mcpu=v1`，而不是减少它。除非您使用`mcpu=v3`，否则程序的许多部分仍然需要 64 位指令和操作。因此，可能更细微的影响是由于在 32 位和 64 位值之间转换需要额外的指令。



对于 v5.2 [2](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fn:4k-limit)之前的较大程序和内核，v2 和 v3 指令集还可以让您将程序大小减少到验证程序规定的 4096 条指令限制以下。然而，这并不是验证者施加的唯一限制。大型程序更常见的问题来源是验证器分析的指令数量限制。

当验证程序分析通过程序的所有路径时，它会计算已经分析了多少条指令，并在给定限制后停止（例如，Linux 5.2+ 上的 100 万条）。我们将验证者分析的指令数称为BPF 程序的*复杂度。*在最坏的情况下，复杂性会随着程序[3](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fn:state-pruning)中条件的数量呈指数增长。



`check-complexity.sh`还报告了每个加载的 BPF 程序的复杂性。我在 Linux 5.10 上执行它并在下图中报告结果。

![img](https://996station.com/wp-content/uploads/2022/11/20221126091347358.png?imageView2/0/format/webp/q/75)



通过单击图例隐藏 v3，我们可以注意到 v1 和 v2 非常接近。然而，前两个版本和最后一个版本之间存在显着差异。v3 指令集有时会降低复杂性，有时会加剧复杂性。添加`mattr=+alu32`具有类似的影响。

目前尚不清楚为什么较新的指令集在减少指令数量时有时会增加复杂性。鉴于它们没有显着修改控制流，可能是它们降低了[验证者状态修剪](https://pchaigno.github.io/ebpf/2021/04/12/bmc-accelerating-memcached-using-bpf-and-xdp.html#bpfs-complexity-constraint)的效率。



总而言之，如果您遇到复杂性问题（即达到验证者的阈值），您需要在进行切换之前仔细测试每个指令集的影响。唯一明确的情况是从 v2 + alu32 切换到 v3，而 v3 几乎总是保持较低的复杂性。

### 结论

我们已经看到，Linux 内核支持的 eBPF 指令集不止一种，而是三种！这些指令集对程序大小和性能有影响，在大多数情况下，您最好设置`mcpu=probe`为使用最新的受支持版本。如果你有非常大的 BPF 程序，版本切换可能会导致内核验证器拒绝，如果你达到了复杂性限制，那么你应该在进行切换之前进行彻底的测试。

1. 据我所知，它应该从 v3.19 开始支持[第一次 helper 调用](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d0003ec01c667b731c139e23de3306a8b328ccf5)，但大多数程序在 v5.0 之前中断，因为不[支持 32 位有符号右移](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2dc6b100f928aac8d7532bf7112d3f8d3f952bad)。 [![↩](https://s.w.org/images/core/emoji/14.0.0/svg/21a9.svg)](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fnref:alu32-support)
2. Linux 5.2 中为特权用户取消了 4096 条指令对程序大小的限制。 [![↩](https://s.w.org/images/core/emoji/14.0.0/svg/21a9.svg)](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fnref:4k-limit)
3. 在实践中，验证者使用状态修剪来识别等效路径并减少要分析的指令数。 [![↩](https://s.w.org/images/core/emoji/14.0.0/svg/21a9.svg)](https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html#fnref:state-pruning)



原文链接

https://pchaigno.github.io/bpf/2021/10/20/ebpf-instruction-sets.html