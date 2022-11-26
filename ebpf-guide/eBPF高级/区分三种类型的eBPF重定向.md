# 区分三种类型的eBPF重定向

Linux 内核中存在三种 eBPF 重定向方式，可能经常让开发人员感到困惑：

1. `bpf_redirect_peer()`
2. `bpf_redirect_neighbor()`
3. `bpf_redirect()`

这篇文章通过按历史顺序深入研究代码来帮助澄清它们，还讨论了现实世界中的用法和相关问题。

# 1 基金会：`bpf_redirect()`, 2015

这个 BPF 助手是在 2015 年通过[这个补丁引入的，](https://github.com/torvalds/linux/commit/27b29f63058d2)

```
bpf: add bpf_redirect() helper
 
Existing bpf_clone_redirect() helper clones skb before redirecting it to RX or
TX of destination netdev.  Introduce bpf_redirect() helper that does that without cloning.
...

```

## 1.1 文档

### 描述

`long bpf_redirect(ifindex, flags)`可以用来**将给定的数据包重定向到给定的网络设备** 用 index 标识`ifindex`。这个助手有点类似于 `bpf_clone_redirect()`，除了数据包没有被克隆，它提供了更高的性能（与`clone_redirect()`提交消息相比提高了 25% pps）。

返回值：**TC/XDP 判决**.

### 比较`bpf_clone_redirect()`

|                             | `bpf_clone_redirect()`   | **`bpf_redirect()`**                                         |
| --------------------------- | ------------------------ | ------------------------------------------------------------ |
| 效率                        | 低（涉及skb clone）      | 高的                                                         |
| 重定向发生的地方            | 内部函数调用             | **函数调用后**（这个函数只返回一个结论，真正的重定向发生在**`skb_do_redirect()`**) |
| 可以在 eBPF 程序之外使用    | 是的                     | 不                                                           |
| 可能会改变底层的 skb 缓冲区 | 是（需要更多的重新验证） | 不                                                           |
| 跨网络重定向                | 不                       | 不                                                           |

## 1.2 内核实现/更改

现在让我们看看 Linux 内核做了哪些改变来支持这个功能。

### 1.增加TC动作类型**`TC_ACT_REDIRECT`**

```
diff --git a/include/uapi/linux/pkt_cls.h b/include/uapi/linux/pkt_cls.h
@@ -87,6 +87,7 @@ enum {
 #define TC_ACT_STOLEN          4
 #define TC_ACT_QUEUED          5
 #define TC_ACT_REPEAT          6
+#define TC_ACT_REDIRECT                7
```

### 2. 添加新的 BPF 助手和系统调用

```
+static u64 bpf_redirect(u64 ifindex, u64 flags, u64 r3, u64 r4, u64 r5)
+{
+       struct redirect_info *ri = this_cpu_ptr(&redirect_info);
+
+       ri->ifindex = ifindex;
+       ri->flags = flags;
+       return TC_ACT_REDIRECT;
+}
```

我们可以看到这个助手只设置`ifindex`然后`flags`返回一个 `TC_ACT_REDIRECT`给调用者，这就是为什么我们说**真正的重定向发生在 bpf_redirect() 完成之后**.

### 3. TC BPF中的流程重定向逻辑

当 BPF 程序（with `bpf_redirect()`in the program）被附加到 TC ingress hook 时， `bpf_redirect()`将在**tc_classify()**方法：

```
@@ -3670,6 +3670,14 @@ static inline struct sk_buff *handle_ing(struct sk_buff *skb,
        switch(tc_classify()) { // <-- bpf_redirect() executes in the tc_classify() method
        ...
        case TC_ACT_QUEUED:
                kfree_skb(skb);
                return NULL;
+       case TC_ACT_REDIRECT:
+               /* skb_mac_header check was done by cls/act_bpf, so
+                * we can safely push the L2 header back before
+                * redirecting to another netdev
+                */
+               __skb_push(skb, skb->mac_len);
+               skb_do_redirect(skb);
+               return NULL;
+
+struct redirect_info {
+       u32 ifindex;
+       u32 flags;
+};
+static DEFINE_PER_CPU(struct redirect_info, redirect_info);
+
+int skb_do_redirect(struct sk_buff *skb)
+{
+       struct redirect_info *ri = this_cpu_ptr(&redirect_info);
+       struct net_device *dev;
+
+       dev = dev_get_by_index_rcu(dev_net(skb->dev), ri->ifindex);
+       ri->ifindex = 0;
+
+       if (BPF_IS_REDIRECT_INGRESS(ri->flags))
+               return dev_forward_skb(dev, skb);
+
+       skb->dev = dev;
+       return dev_queue_xmit(skb);
+}
```

如果返回`TC_ACT_REDIRECT`，`skb_do_redirect()`则将执行真正的重定向。

## 1.3 调用栈

```
pkt -> NIC -> TC ingress -> handle_ing()
                             |-verdict = tc_classify()     // exec BPF code
                             |            |-bpf_redirect() // return verdict
                             |
                             |-switch (verdict) {
                               case TC_ACK_REDIRECT:
                                   skb_do_redirect()       // to the target net device
                                     |-if ingress:
                                     |   dev_forward_skb()
                                     |-else:
                                         dev_queue_xmit()
```

从最后几行我们可以看出 `bpf_redirect()` **支持入口和出口重定向**.

# 2 出口优化：`bpf_redirect_neighbor()`, 2020

`bpf_redirect()`在 Linux 内核中出现 五年后，在[补丁](https://github.com/torvalds/linux/commit/b4ab31414970a)中为其引入了出口端优化：

```
bpf: Add redirect_neigh helper as redirect drop-in
 
Add a redirect_neigh() helper as redirect() drop-in replacement
for the xmit side. Main idea for the helper is to be very similar
in semantics to the latter just that the skb gets injected into
the neighboring subsystem in order to let the stack do the work
it knows best anyway to populate the L2 addresses of the packet
and then hand over to dev_queue_xmit() as redirect() does.
 
This solves two bigger items:
i) skbs don't need to go up to the stack on the host facing veth ingress side for traffic egressing
  the container to achieve the same for populating L2 which also has the huge advantage that
ii) the skb->sk won't get orphaned in ip_rcv_core() when entering the IP routing layer on the host stack.
 
Given that skb->sk neither gets orphaned when crossing the netns
as per 9c4c325 ("skbuff: preserve sock reference when scrubbing
the skb.") the helper can then push the skbs directly to the phys
device where FQ scheduler can do its work and TCP stack gets proper
backpressure given we hold on to skb->sk as long as skb is still
residing in queues.
 
With the helper used in BPF data path to then push the skb to the
phys device, I observed a stable/consistent TCP_STREAM improvement
on veth devices for traffic going container -> host -> host ->
container from ~10Gbps to ~15Gbps for a single stream in my test
environment.
```

## 2.1 比较`bpf_redirect()`

|                                        | `bpf_redirect()` | **`bpf_redirect_neighbor()`**                         |
| -------------------------------------- | ---------------- | ----------------------------------------------------- |
| 支持方向                               | 入口和出口       | **仅出口**                                            |
| 通过内核堆栈填充 L2 地址（邻居子系统） | 不               | 是的 （**根据 pkt 中的 L3 信息填写例如 MAC 地址）**   |
| 跨网络重定向                           | 不               | 不                                                    |
| 其他                                   |                  | `flags`参数保留且必须为 0；目前仅支持 tc BPF 程序类型 |

返回：成功时返回**TC_ACT_REDIRECT**，错误时返回**TC_ACT_SHOT 。**

## 2.2 内核实现/更改

### 1.修改`skb_do_redirect()`，喜欢新的

```
 int skb_do_redirect(struct sk_buff *skb)
 {
        struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
        struct net_device *dev;
+       u32 flags = ri->flags;
 
        dev = dev_get_by_index_rcu(dev_net(skb->dev), ri->tgt_index);
        ri->tgt_index = 0;
@@ -2231,7 +2439,22 @@ int skb_do_redirect(struct sk_buff *skb)
                return -EINVAL;
        }
 
-       return __bpf_redirect(skb, dev, ri->flags);
+       return flags & BPF_F_NEIGH ?
+              __bpf_redirect_neigh(skb, dev) :
+              __bpf_redirect(skb, dev, flags);
+}
```

### 2. 添加`bpf_redirect_neigh()`助手/包装器和系统调用

略，看下面的调用栈。

## 2.3 调用栈

```
skb_do_redirect
  |-__bpf_redirect_neigh(skb, dev) :
      |-__bpf_redirect_neigh_v4
          |-rt = ip_route_output_flow()
          |-skb_dst_set(skb, &rt->dst);
          |-bpf_out_neigh_v4(net, skb)
              |-neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
              |-sock_confirm_neigh(skb, neigh);
              |-neigh_output(neigh, skb, is_v6gw); // xmit with L2 header properly set
                 |-neigh->output()
                    |-neigh_direct_output??
                      |-dev_queue_xmi()

```

请注意，虽然这是对 的优化`bpf_redirec()`，但仍然需要**遍历整个内核堆栈**.

# 3 Ingress优化：`bpf_redirect_peer()`, 2020

在2020 年的[补丁](https://github.com/torvalds/linux/commit/9aa1206e8f482)中引入，

```
bpf: Add redirect_peer helper
 
Add an efficient ingress to ingress netns switch that can be used out of tc BPF
programs in order to redirect traffic from host ns ingress into a container
veth device ingress without having to go via CPU backlog queue [0].
 
For local containers this can also be utilized and path via CPU backlog queue only needs
to be taken once, not twice. On a high level this borrows from ipvlan which does
similar switch in __netif_receive_skb_core() and then iterates via another_round.
This helps to reduce latency for mentioned use cases.

```

## 3.1 比较`bpf_redirect()`

|              | `bpf_redirect()` | **`bpf_redirect_peer()`**                                    |
| ------------ | ---------------- | ------------------------------------------------------------ |
| 支持方向     | 入口和出口       | **仅入口**                                                   |
| 跨网络重定向 | 不               | **是（netns 切换发生在从入口到入口之间，无需经过 CPU 的积压队列）** |
| 其他         |                  | `flags`参数保留且必须为 0；目前仅支持 tc BPF 程序类型；对等设备必须位于不同的网络中 |

返回：成功时返回**TC_ACT_REDIRECT**，错误时返回**TC_ACT_SHOT 。**

## 3.2 内核实现/更改

### 1.添加新的重定向标志

```
diff --git a/net/core/filter.c b/net/core/filter.c
index 5da44b11e1ec..fab951c6be57 100644
--- a/net/core/filter.c
+++ b/net/core/filter.c
@@ -2380,8 +2380,9 @@ static int __bpf_redirect_neigh(struct sk_buff *skb, struct net_device *dev)
 
 /* Internal, non-exposed redirect flags. */
 enum {
-       BPF_F_NEIGH = (1ULL << 1),
-#define BPF_F_REDIRECT_INTERNAL        (BPF_F_NEIGH)
+       BPF_F_NEIGH     = (1ULL << 1),
+       BPF_F_PEER      = (1ULL << 2),
+#define BPF_F_REDIRECT_INTERNAL        (BPF_F_NEIGH | BPF_F_PEER)
```

### 2. 添加助手/系统调用

```
+BPF_CALL_2(bpf_redirect_peer, u32, ifindex, u64, flags)
+{
+       struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
+
+       if (unlikely(flags))
+               return TC_ACT_SHOT;
+
+       ri->flags = BPF_F_PEER;
+       ri->tgt_index = ifindex;
+
+       return TC_ACT_REDIRECT;
+}
```

### 3.允许重新进入TC ingress处理（这里针对对端设备）

```
@@ -5163,7 +5167,12 @@ static int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc,
 skip_taps:
 #ifdef CONFIG_NET_INGRESS
        if (static_branch_unlikely(&ingress_needed_key)) {
-               skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev);
+               bool another = false;
+
+               skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev,
+                                        &another);
+               if (another)
+                       goto another_round;
```

`sch_handle_ingress()`变化：

```
@@ -4974,7 +4974,11 @@ sch_handle_ingress(struct sk_buff *skb, struct packet_type **pt_prev, int *ret,
                 * redirecting to another netdev
                 */
                __skb_push(skb, skb->mac_len);
-               skb_do_redirect(skb);
+               if (skb_do_redirect(skb) == -EAGAIN) {
+                       __skb_pull(skb, skb->mac_len);
+                       *another = true;
+                       break;
+               }
 
 int skb_do_redirect(struct sk_buff *skb)
 {
        struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
+       struct net *net = dev_net(skb->dev);
        struct net_device *dev;
        u32 flags = ri->flags;
-
-       dev = dev_get_by_index_rcu(dev_net(skb->dev), ri->tgt_index);
+       dev = dev_get_by_index_rcu(net, ri->tgt_index);
        ri->tgt_index = 0;
+       ri->flags = 0;
+       if (flags & BPF_F_PEER) {
+               const struct net_device_ops *ops = dev->netdev_ops;
+
+               dev = ops->ndo_get_peer_dev(dev);
+               if (unlikely(!dev || !is_skb_forwardable(dev, skb) || net_eq(net, dev_net(dev))))
+                       goto out_drop;
+               skb->dev = dev;
+               return -EAGAIN;
        }
-
        return flags & BPF_F_NEIGH ?  __bpf_redirect_neigh(skb, dev) : __bpf_redirect(skb, dev, flags);
 }
```

## 3.3 调用栈

[附上我的网络堆栈帖子](http://arthurchiao.art/blog/linux-net-stack-implementation-rx-zh/)中的图片 ，

![img](http://arthurchiao.art/assets/img/linux-net-stack/netif_receive_skb_list_internal.png)

图 进入内核栈：L2 处理步骤

```
__netif_receive_skb_core
  |
  |-// Device driver processing, e.g. update device's rx/tx stats
  |
  |-another_round:  <------------------<-----------+
  |-// Generic XDP processing                      |
  |                                                | with skb->dev changed to the peer device, the next round
  |-// Tap processing if not skipped               | "G-XDP -> TAP -> TC" processings will be for the peer device,
  |                                                | which means we successfully bypassed tons of stuffs
  |-// TC BPF ingress processing if not skipped    | (and entered container's netns from the default/host netns)
  |-sch_handle_ingress(&another)                   | as shown in the above picture
  |-if another:                                    |
  |   goto another_round -------------->-----------+
  |
  |-// Netfilter processing if not skipped
```

一些解释：

1. 第一次执行**`sch_handle_ingress()`**用于当前网络设备（例如`eth0`物理主机）；
2. 如果它返回**`another==true`**，然后执行将转到**`another_round`**; 然后
3. 我们来到**`sch_handle_ingress()`**第二次，这一次，我们在`eth0`重定向到的设备（例如容器内部）的 TC 入口挂钩上执行。

## 3.4 用例和性能评估

Cilium网络解决方案中的两种场景：

1. **物理网卡 -> 容器网卡**重定向
2. **“容器 A -> 容器 B”重定向**在同一个主机

而在 Cilium 中，此行为由专用选项控制**`--enable-host-legacy-routing=true/false`**:

1. With `true`: 关闭对等重定向优化，仍然像往常一样遍历整个内核堆栈；
2. 使用`false`: 打开对等重定向（如果内核支持），预计会获得显着的性能提升。

性能基准参见[Cilium 1.9 Release Notes](https://cilium.io/blog/2020/11/10/cilium-19/#veth)，我们已经在集群中使用 Cilium 1.10.7 + 5.10 内核双重确认基准。

## 3.5 影响和已知问题

### Kubernetes：错误的 Pod 入口统计信息

`kubelet`通过 cadvisor/netlink 收集每个 pod 的网络统计信息（例如 rx_packets、rx_bytes），并通过 10250 指标端口公开这些指标。

> 有关更多信息，请参阅[kubelet 文档](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)。

在 Kubernetes 节点上：

```
$ curl -H 'Authorization: Bearer eyJh...' -X GET -d '{"num_stats": 1,"containerName": "/kubepods","subContainers": true}' --insecure https://127.0.0.1:10250/stats/ > stats.json
```

获取特定 pod 的统计信息：

```
$ cat stats.json | jq '."/kubepods/burstable/pod42ef7dc5-a27f-4ee5-ac97-54c3ce93bc9b/47585f9593"."stats"[0]."network"' | head -n8 | egrep "(rx_bytes|rx_packets|tx_bytes|tx_packets)"
  "rx_bytes": 34344009,
  "rx_packets": 505446,
  "tx_bytes": 5344339889,
  "tx_packets": 6214124,
```

这些统计的数据来源其实来自**sysfs/procfs**. 例如，pod 的 rx_bytes 是通过pod 的网络接口`cat /sys/class/net/<device>/statistics/rx_bytes` 在哪里检索的。`<device>`

**出现问题**使用时`bpf_redirect_peer()`，因为数据包从物理 NIC 的 TC 入口点直接飞到 Pod 的 TC 入口点，这 **跳过 pod 的 NIC 的驱动程序处理步骤**，所以像上面这样的 rx/tx 统计数据将不会正确更新（只有少数数据包会通过驱动程序）。因此，入口统计数据（如 pps/带宽）将几乎为零。



## 作者

arthurchiao

## 原文链接

http://arthurchiao.art/blog/differentiate-bpf-redirects/