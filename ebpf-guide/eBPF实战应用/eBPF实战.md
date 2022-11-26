# eBPF实战

在深入介绍 eBPF 特性之前，让我们 Get Hands Dirty，切切实实的感受 eBPF 程序到底是什么，我们该如何开发 eBPF 程序。随着 eBPF 生态的演进，现在已经有越来越多的工具链用于开发 eBPF 程序，在后文也会详细介绍：

- 基于 bcc 开发：bcc 提供了对 eBPF 开发，前段提供 Python API，后端 eBPF 程序通过 C 实现。特点是简单易用，但是性能较差。
- 基于 libebpf-bootstrap 开发：libebpf-bootstrap 提供了一个方便的脚手架。
- 基于内核源码开发：内核源码开发门槛较高，但是也更加切合 eBPF 底层原理，所以这里以这个方法作为示例。

**内核源码编译**

系统环境如下，采用腾讯云 CVM，Ubuntu 20.04，内核版本 5.4.0。

```
$ uname -a
Linux VM-1-3-ubuntu 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

首先安装必要依赖：

```
sudo apt install -y bison build-essential cmake flex git libedit-dev pkg-config libmnl-dev \
   python zlib1g-dev libssl-dev libelf-dev libcap-dev libfl-dev llvm clang pkg-config \
   gcc-multilib luajit libluajit-5.1-dev libncurses5-dev libclang-dev clang-tools
```

一般情况下推荐采用 apt 方式的安装源码，安装简单而且只安装当前内核的源码，源码的大小在 200M 左右。

```
# apt-cache search linux-source

# apt install linux-source-5.4.0
```

源码安装至 /usr/src/ 目录下。

```
$ ls -hl
total 4.0K
drwxr-xr-x 4 root root 4.0K Nov  9 13:22 linux-source-5.4.0
lrwxrwxrwx 1 root root   45 Oct 15 10:28 linux-source-5.4.0.tar.bz2 -> linux-source-5.4.0/linux-source-5.4.0.tar.bz2
$ tar -jxvf linux-source-5.4.0.tar.bz2
$ cd linux-source-5.4.0

$ cp -v /boot/config-$(uname -r) .config # make defconfig 或者 make menuconfig
$ make headers_install
$ make modules_prepare
$ make scripts     # 可选
$ make M=samples/bpf  # 如果配置出错，可以使用 make oldconfig && make prepare 修复
```

编译成功后，可以在 samples/bpf 目录下看到一系列的目标文件和二进制文件。
**Hello World**
前面说到 eBPF 通常由内核空间程序和用户空间程序两部分组成，现在 samples/bpf 目录下有很多这种程序，内核空间程序以 _kern.c 结尾，用户空间程序以 _user.c 结尾。先不看这些复杂的程序，我们手动写一个 eBPF 程序的 Hello World。
内核中的程序 hello_kern.c：

```
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
    char msg[] = "Hello BPF from houmin!\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";
```

函数入口：

上述代码和普通的C语言编程有一些区别。

- 程序的入口通过编译器的 pragama __section("tracepoint/syscalls/sys_enter_execve") 指定的。
- 入口的参数不再是 argc, argv, 它根据不同的 prog type 而有所差别。我们的例子中，prog type 是 BPF_PROG_TYPE_TRACEPOINT， 它的入口参数就是 void *ctx。

头文件：

```
#include <linux/bpf.h>
```

这个头文件的来源是kernel source header file 。它安装在 /usr/include/linux/bpf.h中。

它提供了bpf 编程需要的很多symbol。例如：

- enum bpf_func_id 定义了所有的kerne helper function 的id
- enum bpf_prog_type 定义了内核支持的所有的prog 的类型。
- struct __sk_buff 是bpf 代码中访问内核struct sk_buff的接口。

等等

```
#include “bpf_helpers.h”
```

来自libbpf ，需要自行安装。我们引用这个头文件是因为调用了bpf_printk()。这是一个kernel helper function。

程序解释：

这里我们简单解读下内核态的 ebpf 程序，非常简单：

- bpf_trace_printk 是一个 eBPF helper 函数，用于打印信息到 trace_pipe (/sys/kernel/debug/tracing/trace_pipe)，详见这里[5]
- 代码声明了 SEC 宏，并且定义了 GPL 的 License，这是因为加载进内核的 eBPF 程序需要有 License 检查，类似于内核模块

加载 BPF 代码：

用户态程序 hello_user.c：

```
#include <stdio.h>
#include "bpf_load.h"

int main(int argc, char **argv)
{
    if(load_bpf_file("hello_kern.o") != 0)
    {
        printf("The kernel didn't load BPF program\n");
        return -1;
    }

    read_trace_pipe();
    return 0;
}
```

在用户态 ebpf 程序中，解读如下：

- 通过 load_bpf_file 将编译出的内核态 ebpf 目标文件加载到内核
- 通过 read_trace_pipe 从 trace_pipe 读取 trace 信息，打印到控制台中

修改 samples/bpf 目录下的 Makefile 文件，在对应的位置添加以下三行：

```
hostprogs-y += hello
hello-objs := bpf_load.o hello_user.o
always += hello_kern.o
```

重新编译，可以看到编译成功的文件：

```
$ make M=samples/bpf
$ ls -hl samples/bpf/hello*
-rwxrwxr-x 1 ubuntu ubuntu 404K Mar 30 17:48 samples/bpf/hello
-rw-rw-r-- 1 ubuntu ubuntu  317 Mar 30 17:47 samples/bpf/hello_kern.c
-rw-rw-r-- 1 ubuntu ubuntu 3.8K Mar 30 17:48 samples/bpf/hello_kern.o
-rw-rw-r-- 1 ubuntu ubuntu  246 Mar 30 17:47 samples/bpf/hello_user.c
-rw-rw-r-- 1 ubuntu ubuntu 2.2K Mar 30 17:48 samples/bpf/hello_user.o
```

进入到对应的目录运行 hello 程序，可以看到输出结果如下：

```
$ sudo ./hello
           <...>-102735 [001] ....  6733.481740: 0: Hello BPF from houmin!

           <...>-102736 [000] ....  6733.482884: 0: Hello BPF from houmin!

           <...>-102737 [002] ....  6733.483074: 0: Hello BPF from houmin!
```

**代码解读**

前面提到 load_bpf_file 函数将 LLVM 编译出来的 eBPF 字节码加载进内核，这到底是如何实现的呢？

经过搜查，可以看到 load_bpf_file 也是在 samples/bpf 目录下实现的，具体的参见 bpf_load.c[6]。



阅读 load_bpf_file 代码可以看到，它主要是解析 ELF 格式的 eBPF 字节码，然后调用 load_and_attach[7] 函数。

在 load_and_attach 函数中，我们可以看到其调用了 bpf_load_program 函数，这是 libbpf 提供的函数。

调用的 bpf_load_program 中的 license、kern_version 等参数来自于解析 eBPF ELF 文件，prog_type 来自于 bpf 代码里面 SEC 字段指定的类型。

```
static int load_and_attach(const char *event, struct bpf_insn *prog, int size)
{
  bool is_socket = strncmp(event, "socket", 6) == 0;
 bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
 bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
 bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
 bool is_raw_tracepoint = strncmp(event, "raw_tracepoint/", 15) == 0;
 bool is_xdp = strncmp(event, "xdp", 3) == 0;
 bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
 bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;
 bool is_cgroup_sk = strncmp(event, "cgroup/sock", 11) == 0;
 bool is_sockops = strncmp(event, "sockops", 7) == 0;
 bool is_sk_skb = strncmp(event, "sk_skb", 6) == 0;
 bool is_sk_msg = strncmp(event, "sk_msg", 6) == 0;
  
  //...
  
 fd = bpf_load_program(prog_type, prog, insns_cnt, license, kern_version,
         bpf_log_buf, BPF_LOG_BUF_SIZE);
 if (fd < 0) {
  printf("bpf_load_program() err=%d\n%s", errno, bpf_log_buf);
  return -1;
 }
  //...
}
```

##  