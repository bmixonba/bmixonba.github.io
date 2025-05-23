# How Linux Routes Packets

This post covers the technical details of packet routing in Linux. Linux
has mechanisms in place to route packets using basic, "destination" based routing,
and advanced or policy-based routing. 

# Background

For details about how the socket is initially created, read my post, [Sockets in the Linux Kernel](https://bmixonba.github.io/2025-05-22-Sockets-in-the-Linux-Kernel/)

## Interfaces

### WiFi/Ethernet

When Linux boots, the devices attached to the chip (peripherals) are registered with the Kernel. In this example,
we are assuming our device uses a Qualcomm chipset. The Qualcomm device is looked in [`drivers/net/ethernet/qualcomm/`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac.c). The qualcomm device is registered as:

```c

static struct platform_driver emac_platform_driver = {
	.probe	= emac_probe,
	.remove = emac_remove,
	.driver = {
		.name		= "qcom-emac",
		.of_match_table = emac_dt_match,
		.acpi_match_table = ACPI_PTR(emac_acpi_match),
	},
	.shutdown = emac_shutdown,
};

module_platform_driver(emac_platform_driver);

```
Figure X. Qualcomm Gigabit ethernet card device registration.

The Qualcomm driver uses the `platform_device` interface to register the card.
[`platform_device`s](https://docs.kernel.org/driver-api/driver-model/platform.html)
is a generic framework for registering integrated peripherials, such as those
found on system-on-chips (SoC). The generic data structure includes various callback
function pointers that the specific device defines and then registers with a call to
`module_platform_driver`.

In this case, the Qualcomm Ethernet Media Access Controller (EMAC) represents the 
Qualcomm Gigabit Ethernet device[example](https://www.cast-inc.com/interfaces/internet-protocol-stacks/emac-1g).
The `.probe` function is callback the Linux kernel calls when the device is powered on. It
is responsible for allocating various data structures, e.g., `struct net_device`, setting
up interupts, locks, and other components necessary for the device to run.

The `emac_probe` function sets up `napi` functions to be called whenever the device receives a 
packet. NAPI (or "new-API") is the updated framework the Linux kernel uses to send and receive
packets on network interfaces. It uses polling to periodically check the send and receive buffers
and processes groups of packets at once instead of using interupts, which are less efficient.

```c
static int emac_probe(struct platform_device *pdev)
{
	struct net_device *netdev;
.
.
.

	/* Initialize queues */
	emac_mac_rx_tx_ring_init_all(pdev, adpt);

	netif_napi_add(netdev, &adpt->rx_q.napi, emac_napi_rtx);

	ret = register_netdev(netdev);
.
.
.

```
Figure X. `emac_probe` function setting up send (TX) and receive (RX) queues in the device. Code in
[`drivers/net/qualcomm/emac/emac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac.c#L592C1-L594C28).


### Rmnet


[link](https://docs.kernel.org/networking/device_drivers/cellular/qualcomm/rmnet.html)

### tun

## Net Stack Initialization

When Linux is booted, its Networking subsystem registers all of the supported protocols. For 
the TCP/IP and UDP/IP stacks, the `inet_init` function in [`af_inet`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L1890) is responsible for this.

```c

static int __init inet_init(void)
{
.
	rc = proto_register(&tcp_prot, 1);
	if (rc)
		goto out;
.

	/*
	 *	Tell SOCKET that we are alive...
	 */

	(void)sock_register(&inet_family_ops);
.
	net_hotdata.tcp_protocol = (struct net_protocol) {
		.handler	=	tcp_v4_rcv,
		.err_handler	=	tcp_v4_err,
		.no_policy	=	1,
		.icmp_strict_tag_validation = 1,
	};
	if (inet_add_protocol(&net_hotdata.tcp_protocol, IPPROTO_TCP) < 0)
.
	ip_init();
.
	tcp_init();
	ip_tunnel_core_init();


}
```
Figure. Network stack initialization in [`af_inet`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L1890).

# Packet Reception 

When a packet is received, the `ip_rcv` function registered with the network stack is called.

## Link Layer

### WiFi

When the Qualcomm card receives a packet, the `emac_napi_rtx` function is called.


```c
/* NAPI */
static int emac_napi_rtx(struct napi_struct *napi, int budget)
{
	struct emac_rx_queue *rx_q =
		container_of(napi, struct emac_rx_queue, napi);
	struct emac_adapter *adpt = netdev_priv(rx_q->netdev);
	struct emac_irq *irq = rx_q->irq;
	int work_done = 0;

	emac_mac_rx_process(adpt, rx_q, &work_done, budget);

	if (work_done < budget) {
		napi_complete_done(napi, work_done);

		irq->mask |= rx_q->intr;
		writel(irq->mask, adpt->base + EMAC_INT_MASK);
	}

	return work_done;
}

```
Figure X. Packet reception code `emac_napi_rtx` in [`drivers/net/qualcomm/emac/emac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac.c#L96).



### Tun device

VPNs are typically configured with a `tun` device and are defined in [`drivers/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c). The `tun` is a character device (and as always, represented as a file). This is backed by
the `tun_struct` structure

```c

struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;

```
Figure. `tun_struct` representing a tun device.



```c
static int __init tun_init(void)
{
	int ret = 0;

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);

	ret = rtnl_link_register(&tun_link_ops);
.
```
Figure. tun registration routine.


```c
/* Ops structure to mimic raw sockets with tun */
static const struct proto_ops tun_socket_ops = {
	.peek_len = tun_peek_len,
	.sendmsg = tun_sendmsg,
	.recvmsg = tun_recvmsg,
};

```
Figure. `tun_socket_ops` callbacks used to receive packets. Defined in [`driver/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c#L955).

```c
static int tun_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		       int flags)
{
```
Figure. Main receive function for tunnel device. Defined in [`driver/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c#L2538)


## Network Layer

```c

/*
 * IP receive entry point
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```
Figure X. The receive routine registered with the kernel, at [`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#558)


```c


/*
 * 	Main IP Receive routine.
 */
static struct sk_buff *ip_rcv_core(struct sk_buff *skb, struct net *net)
{
```
Figure X. The main IP receive routine in Linux in `net/ip_input.c`(https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L454)


```c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int ret;
.
	ret = ip_rcv_finish_core(net, skb, dev, NULL);
.
```
Figure X. The finishing function called with Netfilter hook code, at [`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L433).

![Netfilter calling points for different tables and default chains.](./imgs/Netfilter-packet-flow.png)
(Original source at [Wikipedia](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg))

The function `ip_rcv_finish_core` is ultimately responsible for determining the route the packet is supposed to take.

```c
static int ip_rcv_finish_core(struct net *net,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint)
{
.
	rt = skb_rtable(skb);
.
```
Finish X. Core function for recieving a TCP or UDP packet.

The packet is then delivered to the upper layer protocol (TCP or UDP).

```c
static inline int dst_input(struct sk_buff *skb)
{
	return INDIRECT_CALL_INET(skb_dst(skb)->input,
				  ip6_input, ip_local_deliver, skb);
}
```
Figre X. [net/dst.h](https://github.com/torvalds/linux/blob/master/include/net/dst.h#L467)


```c
INDIRECT_CALLABLE_DECLARE(int udp_rcv(struct sk_buff *));
INDIRECT_CALLABLE_DECLARE(int tcp_v4_rcv(struct sk_buff *));
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
	const struct net_protocol *ipprot;
	int raw, ret;

resubmit:
	raw = raw_local_deliver(skb, protocol);

	ipprot = rcu_dereference(inet_protos[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
			if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb_reason(skb,
						 SKB_DROP_REASON_XFRM_POLICY);
				return;
			}
			nf_reset_ct(skb);
		}
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv,
				      skb);
		if (ret < 0) {
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
			if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
				icmp_send(skb, ICMP_DEST_UNREACH,
					  ICMP_PROT_UNREACH, 0);
			}
			kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
		} else {
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
}

static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_delivery_time(skb);
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
	rcu_read_unlock();

	return 0;
}
```
Figure X. IP code that calls to TCP or UDP receive routines, or sends an ICMP message in [ip_input](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L317).


## Routing Tables

Linux is capable of having multiple routing tables. Each table has one or more
rules associated with it. A user can define up to 252 unique routing tables. The tables
can be defined either using a string or a number, but those are mapped to an integer.
There are also four predefined routing tables, 

1. `CAMPAT`
2. `DEFAULT`
3. `MAIN`
4. `LOCAL`

### COMPAT

This routing table is for background compatibility with older versions of Linux (XXX - I am making this up and need to verify that it is true)

### DEFAULT

The `DEFAULT` routing table is used when no other tables are applicable for a packet.

### MAIN

The `MAIN` routing tables is used for XXX.

### LOCAL

The `LOCAL` routing table is used for packets generated and received by the local processes.

```c

/* Reserved table identifiers */

enum rt_class_t {
	RT_TABLE_UNSPEC=0,
/* User defined values */
	RT_TABLE_COMPAT=252,
	RT_TABLE_DEFAULT=253,
	RT_TABLE_MAIN=254,
	RT_TABLE_LOCAL=255,
	RT_TABLE_MAX=0xFFFFFFFF
};

```
Figure X. [Identifiers for routing tables.](https://elixir.bootlin.com/linux/v6.14.4/source/include/uapi/linux/rtnetlink.h#L355)


# Lifetime of a packet

There are three primary situations in which the routing code is invoked, when
the Linux machine is a Server, a Client, and a Router. The following
subsections will take us through the lifetime of a packet as it traverses the
Linux kernel.

## Server: Remote to Local

When a user writes a server program, like OpenVPN, WireGuard, IPsec, or
ShadowSocks, one of the primary functions invoked in user-space are the
`listen` and `accept` system calls. The following code segments are examples
of running each of these programs as servers. was taken from OpenVPN.

```c
1942 open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
1943 {
.
.
.
2027             if ((ctl_fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)


```
Figure OpenVPN. Code to create a tuntap device in OpenVPN in [openvpn/src/tun.c](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c)
```c

// TODO: Add snippet of code from WireGuard server.

```
Figure WireGuard
```c

// TODO: Add snippet of code from IPsec server.

```
Figure IPsec
```c

// TODO: Add snippet of code from ShadowSocks server.

```
Figure ShadowSocks

The basic patterns is 


```c
sock = socket()
// bind optional. Cant do this in Android because of multiple concurrent networks
getopt()
listen
accept
```

The socket system call creates a socket and returns a file descriptor. 

Socket
```c
 949     if (mark && setsockopt(sd, SOL_SOCKET, SO_MARK, (void *) &mark, sizeof(mark)) != 0)
```



The input function will eventually call the `ip_route_output_slow` function to send the response
out the proper device.

##### Routing outgoing packets.

```c

const struct inet_connection_sock_af_ops ipv4_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = inet_sk_rx_dst_set,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};
EXPORT_IPV6_MOD(ipv4_specific);
.
.
.
/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT.
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */
tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
.
	case TCP_LISTEN:
.
		if (th->syn) {
			if (th->fin) {
				SKB_DR_SET(reason, TCP_FLAGS);
				goto discard;
			}
			icsk->icsk_af_ops->conn_request(sk, skb);
.
}
```
Figure: Main TCP receive function in the Linux kernel at line [6804](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c#L6804).

```c
int tcp_conn_request(struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
.
	tcp_openreq_init(req, &tmp_opt, skb, sk);
.
```
Figure tcp\_conn\_request in [tcp\_ip.c](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c#L7224)

```c

static void tcp_openreq_init(struct request_sock *req,
			     const struct tcp_options_received *rx_opt,
			     struct sk_buff *skb, const struct sock *sk)
.
	ireq->ir_mark = inet_request_mark(sk, skb);
.
```
Figure in tcp\_openreq\_init [tcp\_ip.c](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c#L7096)

```c
static inline u32 inet_request_mark(const struct sock *sk, struct sk_buff *skb)
{
	u32 mark = READ_ONCE(sk->sk_mark);

	if (!mark && READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_fwmark_accept))
		return skb->mark;

	return mark;
}
```
Figure inet\_request\_mark in [inet\_sock.h](https://github.com/torvalds/linux/blob/master/include/net/inet_sock.h#L109)


```c
struct dst_entry *inet_csk_route_req(const struct sock *sk,
				     struct flowi4 *fl4,
				     const struct request_sock *req)
.

	flowi4_init_output(fl4, ireq->ir_iif, ireq->ir_mark,
.
.
			   htons(ireq->ir_num), sk->sk_uid);

	security_req_classify_flow(req, flowi4_to_flowi_common(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
.
	return &rt->dst;
}

```

The `inet_csk_route_req` routine is responsible for routing the packet to the
proper destination. First it builds a flow label4, `fl4`, to look up the route
for the network associated with the socket. The flow label includes the
socket's `mark` which is used for policy-based routing. After initializing 
the flow label with a call to `flowi4\_init\_output`, it performs a security
check to classified the flow label for the socket, and then looks up the
route by invoking `ip_route_output_flow`.
```c

struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4,
				    const struct sock *sk)
{
	struct rtable *rt = __ip_route_output_key(net, flp4);
```
Figure X. In []()

```c
static inline struct rtable *__ip_route_output_key(struct net *net,
						   struct flowi4 *flp)
{
	return ip_route_output_key_hash(net, flp, NULL);
}
```
Figure X. in [route.h](https://github.com/torvalds/linux/blob/master/include/net/route.h#L166).

```c
struct rtable *ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
					const struct sk_buff *skb)
{
.
	rth = ip_route_output_key_hash_rcu(net, fl4, &res, skb);
.
}


struct rtable *ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
					    struct fib_result *res,
					    const struct sk_buff *skb)
{
.
	err = fib_lookup(net, fl4, res, 0);


.
```
Figure X. Main route table lookup routine in [route.c](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2688)


```c

static inline int fib_lookup(struct net *net, struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
.

.
```
Figure X. FIB look up in [`ip_fib.c`](https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L374)


```c


#### IPsec support in Linux 

XFRM is used to support IPsec in the Linux kernel [link](https://docs.cilium.io/en/latest/reference-guides/xfrm/index.html)
int __xfrm_policy_check(struct sock *sk, int dir, struct sk_buff *skb,
			unsigned short family)
{

	nf_nat_decode_session(skb, &fl, family);

```
Figure `__xfrm_policy_check` in [3673](https://github.com/torvalds/linux/blob/master/net/xfrm/xfrm_policy.c#L3673)

#### Routing Incoming packets

When a client or server calls `recv` on a `socket`, fd, that code
eventually calls to the IP code. This code is called by 


```c

int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)



/*
 * 	Main IP Receive routine.
 */
static struct sk_buff *ip_rcv_core(struct sk_buff *skb, struct net *net)
{
	const struct iphdr *iph;


struct rtable *rt_dst_alloc(struct net_device *dev,
			    unsigned int flags, u16 type,
			    bool noxfrm)

			rt->dst.input = ip_local_deliver;

```

```c

static enum skb_drop_reason
ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
		    dscp_t dscp, struct net_device *dev,
		    struct fib_result *res)
{
// Get rid of invalid addresses first


	/*
	 *	Now we are ready to route packet.
	 */
//
	fl4.flowi4_mark = skb->mark;

	fl4.flowi4_uid = sock_net_uid(net, NULL);
//
	err = fib_lookup(net, &fl4, res, 0);
	if (err != 0) {
		if (!IN_DEV_FORWARD(in_dev))
	err = fib_lookup(net, &fl4, res, 0);

```
Figure `ip_route_input_slow` in [route.c](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2908)

The call to `fib_lookup` finds the correct route for the incoming packet. `fib_lookup` has two definitions, one for
when the kernel supports only one routing table, and one for when multiple tables are available.

```c

static inline int fib_lookup(struct net *net, struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{

	flags |= FIB_LOOKUP_NOREF;
	if (net->ipv4.fib_has_custom_rules)
		return __fib_lookup(net, flp, res, flags);


```
Figure X. `fig_lookup` for multiple tables [374](https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L374).


When mutliple tables are defined, the routing code calls into `__fib_lookup` in
[`fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L108).

```c
int __fib_lookup(struct net *net, struct flowi4 *flp,
		 struct fib_result *res, unsigned int flags)
{
.
	err = fib_rules_lookup(net->ipv4.rules_ops, flowi4_to_flowi(flp), 0, &arg);

}
.

static int fib_rule_match(struct fib_rule *rule, struct fib_rules_ops *ops,
			  struct flowi *fl, int flags,
			  struct fib_lookup_arg *arg)
{
	int iifindex, oifindex, ret = 0;

	if ((rule->mark ^ fl->flowi_mark) & rule->mark_mask)
		goto out;

	if (rule->tun_id && (rule->tun_id != fl->flowi_tun_key.tun_id))
		goto out;

	if (rule->l3mdev && !l3mdev_fib_rule_match(rule->fr_net, fl, arg))
		goto out;

	if (uid_lt(fl->flowi_uid, rule->uid_range.start) ||
	    uid_gt(fl->flowi_uid, rule->uid_range.end))
		goto out;



.

int fib_rules_lookup(struct fib_rules_ops *ops, struct flowi *fl,
		     int flags, struct fib_lookup_arg *arg)
{


```
Figure X. in `fig_rules.c` Line [108](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L108)


## Client: Local to Remote 

## Router: Remote to Remote 
