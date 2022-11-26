# 构建基于eBPF的协议跟踪器,eBPF捕获生产流量的实用指南

> - 使用tcpdump 等典型网络捕获工具[监控 HTTP 会话](https://www.datadoghq.com/blog/ebpf-guide/#challenges-with-monitoring-http-sessions)的挑战
> - [eBPF 是什么](https://www.datadoghq.com/blog/ebpf-guide/#what-exactly-is-ebpf)以及它如何克服这些挑战
> - 如何[构建基于 eBPF 的协议跟踪器](https://www.datadoghq.com/blog/ebpf-guide/#building-an-ebpf-based-traffic-capturer)以最小难度和低开销捕获生产流量
> - 使用 eBPF 捕获生产流量的实用指南

监视 HTTP 会话提供了一种潜在的强大方法来了解您的 Web 服务器，但在实践中，这样做可能很复杂且占用大量资源。[扩展的 Berkeley 数据包过滤器 (eBPF)](https://ebpf.io/)技术使您能够克服这些挑战，为您提供一种简单高效的方法来处理应用层流量以满足您的故障排除需求。

在这篇文章中，我们将介绍：

- 使用tcpdump 等典型网络捕获工具[监控 HTTP 会话](https://www.datadoghq.com/blog/ebpf-guide/#challenges-with-monitoring-http-sessions)的挑战
- [eBPF 是什么](https://www.datadoghq.com/blog/ebpf-guide/#what-exactly-is-ebpf)以及它如何克服这些挑战
- 如何[构建基于 eBPF 的协议跟踪器](https://www.datadoghq.com/blog/ebpf-guide/#building-an-ebpf-based-traffic-capturer)以最小难度和低开销捕获生产流量

## [监控 HTTP 会话的挑战](https://www.datadoghq.com/blog/ebpf-guide/#challenges-with-monitoring-http-sessions)

当您注意到 HTTP 服务器的行为异常时，确定导致问题的原因并不总是那么容易。通常，您可能会通过查看配置设置或筛选日志条目以获取见解来开始故障排除。但是，如果这些初步调查没有充分阐明问题，您接下来可能会开始考虑如何检查 HTTP 流量以收集更多信息。

查看构成 HTTP 会话的请求和响应线程中的详细信息确实可以提供有关影响 HTTP 服务器的问题的重要信息。但在实践中，分析 HTTP 会话数据很复杂，最常用的网络流量捕获方法对此用途有限。



[例如， Tcpdump](https://www.tcpdump.org/)是用于捕获生产中流量的最常见解决方案之一。但是 tcpdump 并没有整齐地显示 HTTP 会话供您分析，它只是为您提供数百兆字节（甚至千兆字节）的单独数据包，然后您需要将这些数据包梳理并拼凑成会话。

使用 tcpdump 的另一种方法是在源代码中添加一个算法，自动排序和显示有关 HTTP 会话的信息。但是，此方法需要您对生产代码进行检测，并且以这种方式处理所有 HTTP 流量会导致严重的性能损失。



这正是[eBPF](https://www.infoq.com/articles/gentle-linux-ebpf-introduction/)的用武之地。eBPF于 2014 年发布，是 Linux 应用程序在 Linux 内核空间中执行代码的一种机制。借助 eBPF，您可以创建功能强大的流量捕获工具，其功能远远超过标准工具。更具体地说，eBPF 允许您添加多个过滤层并直接从内核捕获流量。这些功能将输出限制为仅相关数据，使您能够处理和过滤您的应用程序流量，即使在吞吐量很高时也只会对性能产生有限的影响。

## [eBPF到底是什么？](https://www.datadoghq.com/blog/ebpf-guide/#what-exactly-is-ebpf)

为了更好地理解 eBPF，了解一点原始或经典的 Berkeley Packet Filter (BPF) 会有所帮助。BPF 定义了一种数据包过滤器，实现为虚拟机，可以在 Linux 内核中运行。在 BPF 之前，数据包过滤器仅在用户空间运行，这比内核级过滤更占用 CPU。BPF 通常用于需要高效捕获和分析数据包的程序。例如，它允许 tcpdump 非常快速地过滤掉不相关的数据包。

但是请注意，BPF（以及 tcpdump）快速处理*数据包*的能力不足以处理 HTTP*会话*。BPF 允许您检查单个数据包的有效负载。另一方面，HTTP 会话通常由多个 TCP 数据包组成，因此需要在第 7 层（应用层）对流量进行更复杂的处理。BPF 不提供处理此类过滤的方法。



BPF 的 eBPF 扩展正是为此目的而创建的。这种较新的技术允许您向内核系统调用 (syscalls) 和函数（包括与网络相关的函数）添加hook，以提供对流量有效负载和函数结果（成功/失败）的可见性。因此，使用 eBPF，您可以独立于向内核发送数据的应用程序启用复杂的功能和网络流量处理，包括第 7 层过滤。多亏了 eBPF，事实上，许多公司现在可以提供安全性和可观察性功能，甚至不需要您检测服务器端代码——或者完全不了解该代码。有关 eBPF 的更多信息，您可以访问 ebpf.io 上的项目[页面](https://ebpf.io/)。

现在我们已经介绍了什么是 eBPF 以及它使我们能够做什么，我们可以开始构建 eBPF 协议跟踪器。

## [构建基于 eBPF 的流量捕获器](https://www.datadoghq.com/blog/ebpf-guide/#building-an-ebpf-based-traffic-capturer)

在本演练中，我们将使用 eBPF 捕获由 Go 编写的 REST API 服务器处理的网络流量。作为典型的 eBPF 代码，我们的捕获工具将包括一个执行系统调用hook的*内核代理*和一个处理通过hook从内核发送的事件的*用户模式代理。*

> **笔记**
>
> 该演练的灵感来自[Pixie Lab](https://pixielabs.ai/)基于 eBPF 的数据收集器，示例代码片段取自 Pixie tracer[公共 repo](https://github.com/pixie-io/pixie)。演练的完整代码可以在[这里](https://github.com/DataDog/ebpf-training/tree/main/workshop1)找到。为简单起见，下面的代码片段仅代表关键部分。

要执行此演练，我们需要一台运行任何基本 Linux 发行版（例如 Ubuntu 或 Debian）并安装以下组件的机器：

- [BPF 编译器集合 (BCC) 工具](https://www.containiq.com/post/bcc-tools)包。按照[此处](https://github.com/iovisor/bcc/blob/master/INSTALL.md)的安装指南进行操作。
- Golang 版本 1.16+。按照[此处](https://go.dev/doc/install)的安装指南进行操作。

为简单起见，我们创建了一个具有上述依赖项的 Docker 容器（基于 Debian）。查看[存储库](https://github.com/DataDog/ebpf-training/tree/main/workshop1)以获取运行说明。

### [启动网络服务器](https://www.datadoghq.com/blog/ebpf-guide/#starting-the-web-server)

以下是接收单个 POST 请求并使用随机生成的负载进行响应的 HTTP Web 服务器的示例。

```
package main
 
...
 
const (
  defaultPort    = "8080"
  maxPayloadSize = 10 * 1024 * 1024 // 10 MB
  letterBytes    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
)
 
...
 
// customResponse holds the requested size for the response payload.
type customResponse struct {
  Size int `json:"size"`
}
 
func postCustomResponse(context *gin.Context) {
 
  var customResp customResponse
 
  if err := context.BindJSON(&customResp); err != nil {
    _ = context.AbortWithError(http.StatusBadRequest, err)
	return
  }
  if customResp.Size > maxPayloadSize {
	_ = context.AbortWithError(http.StatusBadRequest, fmt.Errorf("requested size %d is bigger than max allowed %d", customResp, maxPayloadSize))
	return
  }
 
  context.JSON(http.StatusOK, map[string]string{"answer": randStringBytes(customResp.Size)})
}
 
func main() {
  engine := gin.New()
 
  engine.Use(gin.Recovery())
  engine.POST("/customResponse", postCustomResponse)
  
  port := os.Getenv("PORT")
  
  if port == "" {
		port = defaultPort
  }
 
  fmt.Printf("listening on 0.0.0.0:%s\n", port)
 
  if err := engine.Run(fmt.Sprintf("0.0.0.0:%s", port)); err != nil {
	log.Fatal(err)
  }
}
```

我们可以使用以下命令运行此服务器：

```
go run server.go
```

接下来，我们可以使用以下命令来触发服务器的输出并验证服务器是否正常工作：

```
curl -X POST http://localhost:8080/customResponse -d '{"size": 100}'
```

### [查找要跟踪的系统调用](https://www.datadoghq.com/blog/ebpf-guide/#finding-the-syscalls-to-track)

一旦 Web 服务器启动并运行，在构建跟踪器之前我们需要做的第一件事就是确定哪些系统调用正在用于 HTTP 通信。我们将使用该`strace`工具来完成这项任务。

更具体地说，我们可以运行服务器`strace`并使用该`-f`选项从服务器线程捕获系统调用。通过该`-o`选项，我们可以将所有输出写入一个我们可以命名的文本文件**系统调用转储.txt**. 为此，我们运行以下命令：

```
sudo strace -f -o syscalls_dump.txt go run server.go
```

接下来，如果我们重新运行上面的`curl`命令并检查**系统调用转储.txt**，我们可以观察到以下情况：

```
38988 accept4(3,  <unfinished ...>
38987 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
38988 <... accept4 resumed>{sa_family=AF_INET, sin_port=htons(57594), sin_addr=inet_addr("127.0.0.1")}, [112->16], SOCK_CLOEXEC|SOCK_NONBLOCK) = 7
...
38988 read(7,  <unfinished ...>
38987 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>
38988 <... read resumed>"POST /customResponse HTTP/1.1\r\nH"..., 4096) = 175
...
38988 write(7, "HTTP/1.1 200 OK\r\nContent-Type: a"..., 237 <unfinished ...>
...
38989 close(7)
```

我们可以看到，起初，服务器使用`accept4`系统调用来接受新连接。我们还可以看到新套接字的文件描述符 (FD) 是 7（系统调用的返回码）。此外，我们可以看到对于每个其他系统调用，第一个参数（即 FD）是 7，因此所有操作都发生在同一个套接字上。

这是流程：

1. 使用`accept4`系统调用接受新连接。
2. `read`使用套接字文件描述符上的系统调用从套接字中读取内容。
3. `write`使用套接字文件描述符上的系统调用将响应写入套接字。
4. `close`最后，使用系统调用关闭文件描述符。

现在我们了解了服务器是如何工作的，我们可以继续构建我们的 HTTP 捕获工具。

### [构建内核代理（eBPF HOOK）](https://www.datadoghq.com/blog/ebpf-guide/#building-the-kernel-agent-ebpf-hooks)

[BCC](https://www.containiq.com/post/bcc-tools)和[libbpf](https://www.containiq.com/post/libbpf)是两个主要的开发框架，可用于为 BPF 和 eBPF 创建内核代理。为简单起见，我们将在本演练中使用 BCC 框架，因为它在今天更为普遍。（不过，一般来说，我们建议使用 libbpf。有关这些框架的更多信息，请参阅[本文](https://devops.com/libbpf-vs-bcc-for-bpf-development/)。）

为了构建内核代理，我们将实现八个hook（用于`accept4`、`read`、`write`和`close`系统调用的入口和出口hook）。钩子驻留在内核中，用 C 语言编写。我们需要所有这些钩子的组合来执行完整的捕获过程。在创建内核代理时，我们还将使用辅助结构和映射来存储系统调用的参数。我们将在下面解释这些元素中的每一个的基础知识，但要了解更多信息，您还可以在我们的存储库中查看整个[内核代码](https://github.com/seek-ret/ebpf-training/blob/main/workshop1/capture-traffic/sourcecode.c)。

#### [hook accept4系统调用](https://www.datadoghq.com/blog/ebpf-guide/#hooking-the-accept4-syscall)

首先，我们需要hook `accept4`系统调用。在 eBPF 中，我们可以在每个系统调用进入和退出时（换句话说，就在代码运行之前和之后）放置一个钩子。该条目对于获取系统调用的输入参数很有用，而返回对于了解系统调用是否按预期工作很有用。

在下面的代码片段中，我们声明了一个结构来将输入参数保存在`accept4`系统调用的入口中。然后我们在系统调用的出口中使用此信息，我们可以在其中确定系统调用是否成功。

```
// Copyright (c) 2018 The Pixie Authors.
// Licensed under the Apache License, Version 2.0 (the "License")
// Original source: https://github.com/pixie-io/pixie/blob/main/src/stirling/source%5C_connectors/socket%5C_tracer/bcc%5C_bpf/socket%5C_trace.c 
 
// A helper struct that holds the addr argument of the syscall.
struct accept_args_t {
 struct sockaddr_in* addr;
};
 
// A helper map that will help us cache the input arguments of the accept syscall
// between the entry hook and the return hook.
BPF_HASH(active_accept_args_map, uint64_t, struct accept_args_t);
 
// Hooking the entry of accept4
// the signature of the syscall is int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
 // Getting a unique ID for the relevant thread in the relevant pid.
 // That way we can link different calls from the same thread.
 
 uint64_t id = bpf_get_current_pid_tgid();
 
 // Keep the addr in a map to use during the accept4 exit hook.
 struct accept_args_t accept_args = {};
 accept_args.addr = (struct sockaddr_in *)addr;
 active_accept_args_map.update(&id, &accept_args);
 
 return 0;
}
 
// Hooking the exit of accept4
int syscall__probe_ret_accept4(struct pt_regs* ctx) {
 uint64_t id = bpf_get_current_pid_tgid();
 
 // Pulling the addr from the map.
 struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
 // If the id exist in the map, we will get a non empty pointer that holds
 // the input address argument from the entry of the syscall.
 if (accept_args != NULL) {
   process_syscall_accept(ctx, id, accept_args);
 }
 
 // Anyway, in the end clean the map.
 active_accept_args_map.delete(&id);
 
 return 0;
}
```

上面的代码片段向我们展示了hook系统调用的入口和出口的最少代码，以及将输入参数保存在系统调用入口中以便稍后在系统调用出口中使用的方法。

我们为什么要做这个？由于我们无法知道系统调用在其进入期间是否会成功，并且我们无法在其退出期间访问输入参数，因此我们需要存储参数，直到我们确定系统调用成功为止。只有这样我们才能执行我们的逻辑。



我们的特殊逻辑在 中`process_syscall_accept`，它检查系统调用是否成功完成。然后，我们将连接信息保存在全局映射中，以便我们可以在其他系统调用（`read`、`write`和`close`）中使用它。

在下面的代码片段中，我们创建了一个函数 ( `process_syscall_accept`) 供`accept4`钩子使用，并在我们自己的映射中注册与服务器建立的任何新连接。然后，在代码片段的最后一部分，我们提醒用户模式代理服务器接受了新连接。

```
// Copyright (c) 2018 The Pixie Authors.
// Licensed under the Apache License, Version 2.0 (the "License")
// Original source: https://github.com/pixie-io/pixie/blob/main/src/stirling/source%5C_connectors/socket%5C_tracer/bcc%5C_bpf/socket%5C_trace.c 
 
// A struct representing a unique ID that is composed of the pid, the file
// descriptor and the creation time of the struct.
struct conn_id_t {
  // Process ID
  uint32_t pid;
 
  // The file descriptor to the opened network connection.
  int32_t fd;
 
  // Timestamp at the initialization of the struct.
  uint64_t tsid;
};
 
// This struct contains information collected when a connection is established,
// via an accept4() syscall.
struct conn_info_t {
  // Connection identifier.
  struct conn_id_t conn_id;
 
  // The number of bytes written/read on this connection.
  int64_t wr_bytes;
  int64_t rd_bytes;
 
  // A flag indicating we identified the connection as HTTP.
  bool is_http;
};
 
// A struct describing the event that we send to the user mode upon a new connection.
struct socket_open_event_t {
  // The time of the event.
  uint64_t timestamp_ns;
 
  // A unique ID for the connection.
  struct conn_id_t conn_id;
 
  // The address of the client.
  struct sockaddr_in addr;
};
 
// A map of the active connections. The name of the map is conn_info_map
// the key is of type uint64_t, the value is of type struct conn_info_t,
// and the map won't be bigger than 128KB.
BPF_HASH(conn_info_map, uint64_t, struct conn_info_t, 131072);
 
// A perf buffer that allows us send events from kernel to user mode.
// This perf buffer is dedicated for special type of events - open events.
BPF_PERF_OUTPUT(socket_open_events);
 
// A helper function that checks if the syscall finished successfully and if it did
// saves the new connection in a dedicated map of connections
static __inline void process_syscall_accept(struct pt_regs* ctx, uint64_t id, const struct accept_args_t* args) {
  // Extracting the return code, and checking if it represent a failure,
  // if it does, we abort as we have nothing to do.
  int ret_fd = PT_REGS_RC(ctx);
 
  if (ret_fd <= 0) {
     return;
  }
 
  struct conn_info_t conn_info = {};
  uint32_t pid = id >> 32;
  conn_info.conn_id.pid = pid;
  conn_info.conn_id.fd = ret_fd;
  conn_info.conn_id.tsid = bpf_ktime_get_ns();
 
  uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)ret_fd;
  // Saving the connection info in a global map, so in the other syscalls  
  // (read, write and close) we will be able to know that we have seen   
  // the connection  
  conn_info_map.update(&pid_fd, &conn_info);
 
  // Sending an open event to the user mode, to let the user mode know that we   
  // have identified a new connection. 
  struct socket_open_event_t open_event = {};
  open_event.timestamp_ns = bpf_ktime_get_ns();
  open_event.conn_id = conn_info.conn_id;
  bpf_probe_read(&open_event.addr, sizeof(open_event.addr), args->addr);
 
  socket_open_events.perf_submit(ctx, &open_event, sizeof(struct socket_open_event_t));
}
```

#### [hook read和write系统调用](https://www.datadoghq.com/blog/ebpf-guide/#hooking-the-read-and-write-syscalls)

在以下代码片段中，我们为`read`系统调用创建了hook。您可以看到我们编写的第一个钩子 (for `accept4`) 和这个新钩子之间的相似之处。以下代码使用类似的帮助程序结构和映射，并定义相同的整体操作序列（hook进入和退出、验证退出代码和处理有效负载）。

```
// Copyright (c) 2018 The Pixie Authors.
// Licensed under the Apache License, Version 2.0 (the "License")
// Original source: https://github.com/pixie-io/pixie/blob/main/src/stirling/source%5C_connectors/socket%5C_tracer/bcc%5C_bpf/socket%5C_trace.c 
 
// A helper struct to cache input argument of read/write syscalls between the
// entry hook and the exit hook.
struct data_args_t {
  int32_t fd;
  const char* buf;
};
 
// Helper map to store read syscall arguments between entry and exit hooks.
BPF_HASH(active_read_args_map, uint64_t, struct data_args_t);
 
// original signature: ssize_t read(int fd, void *buf, size_t count);
int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  uint64_t id = bpf_get_current_pid_tgid();
  
  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.buf = buf;
  active_read_args_map.update(&id, &read_args);
  
  return 0;
}
 
int syscall__probe_ret_read(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
 
  // The return code the syscall is the number of bytes read as well.
  ssize_t bytes_count = PT_REGS_RC(ctx); 
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
      // kIngress is an enum value that allows the process_data function
      // to know whether the input buffer is incoming or outgoing.
      process_data(ctx, id, kIngress, read_args, bytes_count);
  }
  
  active_read_args_map.delete(&id);
  return 0;
}
```

在以下代码片段中，我们创建了辅助函数来处理`read`系统调用。我们的辅助函数通过检查读取的字节数来确定`read`系统调用是否成功完成。然后它检查正在读取的数据是否描述 HTTP。如果是这样，我们将它作为事件发送到用户模式。

```
// Copyright (c) 2018 The Pixie Authors.
// Licensed under the Apache License, Version 2.0 (the "License")
// Original source: https://github.com/pixie-io/pixie/blob/main/src/stirling/source%5C_connectors/socket%5C_tracer/bcc%5C_bpf/socket%5C_trace.c 
 
// Data buffer message size. BPF can submit at most this amount of data to a perf buffer.
// Kernel size limit is 32KiB. See   for more details.
#define MAX_MSG_SIZE 30720  // 30KiB
 
struct socket_data_event_t {
  // We split attributes into a separate struct, because BPF gets upset if you do lots of
  // size arithmetic. This makes it so that its attributes are followed by a message.
  struct attr_t {
    // The timestamp when syscall completed (return probe was triggered).
    uint64_t timestamp_ns;
 
    // Connection identifier (PID, FD, etc.).
    struct conn_id_t conn_id;
    
    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    enum traffic_direction_t direction;
    
    // The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    uint32_t msg_size;
    
    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    uint64_t pos;
  } attr;
 
  char msg[MAX_MSG_SIZE];
};
 
// Perf buffer to send to the user-mode the data events.
BPF_PERF_OUTPUT(socket_data_events);
 
...
 
// A helper function that handles read/write syscalls.
static inline __attribute__((__always_inline__)) void process_data(struct pt_regs* ctx, uint64_t id,
                                                               enum traffic_direction_t direction,
                                                               const struct data_args_t* args, ssize_t bytes_count) {
  // Always check access to pointers before accessing them.
  if (args->buf == NULL) {
      return;
  }
  
  // For read and write syscall, the return code is the number of bytes written or read, so zero means nothing
  // was written or read, and negative means that the syscall failed. Anyhow, we have nothing to do with that syscall.
  if (bytes_count <= 0) {
      return;
  }
  
  uint32_t pid = id >> 32;
  uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)args->fd;
  struct conn_info_t* conn_info = conn_info_map.lookup(&pid_fd);
  if (conn_info == NULL) {
      // The FD being read/written does not represent an IPv4 socket FD.
      return;
  }
  
  // Check if the connection is already HTTP, or check if that's a new connection, check protocol and return true if that's HTTP.
  if (is_http_connection(conn_info, args->buf, bytes_count)) {
      // allocate a new event.
      uint32_t kZero = 0;
      struct socket_data_event_t* event = socket_data_event_buffer_heap.lookup(&kZero);
      if (event == NULL) {
          return;
      }
  
      // Fill the metadata of the data event.
      event->attr.timestamp_ns = bpf_ktime_get_ns();
      event->attr.direction = direction;
      event->attr.conn_id = conn_info->conn_id;
  
      // Another helper function that splits the given buffer to chunks if it is too large.
      perf_submit_wrapper(ctx, direction, args->buf, bytes_count, conn_info, event);
  }
  
  // Update the conn_info total written/read bytes.
  switch (direction) {
      case kEgress:
          conn_info->wr_bytes += bytes_count;
          break;
      case kIngress:
          conn_info->rd_bytes += bytes_count;
          break;
  }
}
```

接下来我们可以构建系统调用，这与系统调用hoo `write`非常相似。`read`（作为提醒，您可以查看[我们的 repo 中的相关代码](https://github.com/seek-ret/ebpf-training/blob/main/workshop1/capture-traffic/sourcecode.c)。）

#### [hook close系统调用](https://www.datadoghq.com/blog/ebpf-guide/#hooking-the-close-syscall)

此时，我们只需要处理`close`系统调用，就完成了。这里的hook也与其他hook非常相似。有关详细信息，请参阅[我们的存储库](https://github.com/DataDog/ebpf-training/blob/main/workshop1/capture-traffic/sourcecode.c)。

### [构建用户模式代理](https://www.datadoghq.com/blog/ebpf-guide/#building-the-user-mode-agent)

用户模式代理是使用[gobpf](https://github.com/iovisor/gobpf)库用 Go 语言编写的。该代理从文件中读取内核代码，并在客户端用户模式代理启动期间使用[Clang 工具在运行时编译源代码。](https://clang.llvm.org/)

以下部分仅描述其主要方面。有关完整代码，请参阅[本演练的存储库](https://github.com/DataDog/ebpf-training/blob/main/workshop1/capture-traffic/main.go)。

第一步是编译代码：

```
bpfModule := bcc.NewModule(string(bpfSourceCodeContent), nil)
defer bpfModule.Close()
```

然后，我们创建一个连接工厂，负责保存所有连接实例、打印就绪连接以及删除不活动或格式错误的连接。

```
// Create connection factory and set 1m as the inactivity threshold
// Meaning connections that didn't get any event within the last minute are being closed.
connectionFactory := connections.NewFactory(time.Minute)
// A go routine that runs every 10 seconds and prints ready connections
// And deletes inactive or malformed connections.
go func() {
  for {
		connectionFactory.HandleReadyConnections()
		time.Sleep(10 * time.Second)
  }
}()
```

接下来，我们加载 perf 缓冲区处理程序，它从我们的内核hook接收输出并处理它们：

```
if err := bpfwrapper.LaunchPerfBufferConsumers(bpfModule, connectionFactory); err != nil {
  log.Panic(err)
}
```

请注意，每个 perf 缓冲区处理程序都通过通道 ( `inputChan`) 获取事件，并且每个事件都是字节数组 ( `[]byte`) 类型。我们会将每个事件转换为该结构的 Golang 表示。

```
// ConnID is a conversion of the following C-Struct into GO.
// struct conn_id_t {
//    uint32_t pid;
//    int32_t fd;
//    uint64_t tsid;
// };.
type ConnID struct {
  PID  uint32
  FD   int32
  TsID uint64
}
 
...
```

接下来我们需要修复事件的时间戳，因为内核模式返回单调时钟而不是实时时钟。然后，我们用新事件更新连接对象字段。

```
func socketCloseEventCallback(inputChan chan []byte, connectionFactory *connections.Factory) {
  for data := range inputChan {
    if data == nil {
     return
    }
 
    var event structs.SocketCloseEvent
    if err := binary.Read(bytes.NewReader(data), bpf.GetHostByteOrder(), &event); err != nil {
     log.Printf("Failed to decode received data: %+v", err)
     continue
    }
    event.TimestampNano += settings.GetRealTimeOffset()
    connectionFactory.GetOrCreate(event.ConnID).AddCloseEvent(event)
  }
}
```

对于最后一部分，我们附上hook。

```
if err := bpfwrapper.AttachKprobes(bpfModule); err != nil {
  log.Panic(err)
}
```

## [测试示踪剂](https://www.datadoghq.com/blog/ebpf-guide/#testing-the-tracer)

要测试新的跟踪器，首先向 HTTP 服务器发送客户端 curl 请求：

![img](https://996station.com/wp-content/uploads/2022/11/20221126125811381.png?imageView2/0/format/webp/q/75)

嗅探器从 curl 请求中捕获以下信息：

![img](https://996station.com/wp-content/uploads/2022/11/20221126125822793.png?imageView2/0/format/webp/q/75)

如我们所见，我们能够同时捕获 HTTP 请求和响应，尽管内核中没有与 HTTP 相关的函数。我们仅通过使用 eBPF HOOK与 HTTP 通信关联的系统调用，就成功地检索了完整的有效负载——包括请求和响应的主体。

## [概括](https://www.datadoghq.com/blog/ebpf-guide/#summary)

我们已经完成了为 HTTP 会话流量创建基于 eBPF 的协议跟踪器的过程。如您所见，理解系统调用并为它们实现第一个钩子是最困难的部分。一旦你学会了如何实现你的第一个系统调用钩子，编写其他类似的钩子就会变得容易得多。

除了 HTTP 会话监控之外，团队还可以使用 eBPF 监控任何类型的应用程序级流量。实际上，Datadog 使用 eBPF 的这些功能让您可以了解环境的更多方面，而无需您检测任何代码。例如，Datadog 最近利用 eBPF 构建了[Universal Service Monitoring](https://www.datadoghq.com/blog/universal-service-monitoring-datadog/)，它仅通过监控应用程序级别的流量，就可以让团队检测到其基础设施中运行的所有服务。2022年8月，Datadog还[宣布收购Seekret](https://www.datadoghq.com/about/latest-news/press-releases/datadog-acquires-seekret-to-make-api-observability-accessible/)，其技术利用 eBPF 让组织轻松发现和管理其环境中的 API。Datadog 计划将这些功能整合到其平台中，并使用 eBPF 构建额外的强大功能，以改变团队管理其资源的健康、可用性和安全性的方式。



有关 eBPF 如何工作以及 Datadog 如何使用它的更多深入信息，您可以观看我们的[Datadog on eBPF 视频](https://www.youtube.com/watch?v=58KtGtpn0_g)。要开始使用 Datadog，您可以注册我们的[14 天免费试用](https://www.datadoghq.com/blog/ebpf-guide/#)。

## [参考](https://www.datadoghq.com/blog/ebpf-guide/#references)

- [pixie: Instant Kubernetes-Native Application Observability](https://github.com/pixie-io/pixie) - Kubernetes 应用程序的开源可观察性工具,下载pixie的源码_GitHub_帮酷
- [eBPF - 介绍、教程和社区资源](https://ebpf.io/)
- [eBPF 简介](https://www.infoq.com/articles/gentle-linux-ebpf-introduction/)

## 作者

盖·阿比特曼

## 原文链接

https://www.datadoghq.com/blog/ebpf-guide/