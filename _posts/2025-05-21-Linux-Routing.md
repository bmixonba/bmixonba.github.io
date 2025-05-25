# How Linux Routes Packets

This post covers the technical details of packet routing in Linux. Linux
has mechanisms in place to route packets using basic, "destination" based routing,
and advanced or policy-based routing. Part of the motivation for this deepdive
was the observation and subsequently exploited vulnerability by one of
my buddies, William Tolley. He found that when a VPN is running on Android,
an attacker can spoof packets to the tun interface that match an existing 
connection and that the Android device, more specifically, the process
with the connection, will respond. This went on to become known as the
blind in/on-path attack, this one being the socalled client-side attack.

Part of the reason this is concerning is because in theory, the Android device
should not respond to such packets. Why is that? Because the tun interface
is isolated from the outside world in theory. The fact that it responds
is a clear violation of non-interference and demonstrates that something
is going on that prevents the network stack from properly enforcing
process isolation. Process isolation is a fundamental OS security concept
and when it is violated, bad things tend to happen. Their assessment 
of the issue was that because mobile devices have multiple interfaces, are constantly moving around,
pinging various cell towers, and receiving new IP addresses, it is not possible
to truly enforce the "strong-host" model, though the Android networking
team has made attempts to use various Linux constructs, such as 
multiple routing tables, network name spaces, Netfilter rules, 
and firewall marks (`fwmark`), to simulate the strong-host model. 
What this means at the end of the day is that Android uses policy based routing
to make the VPN service work without completely ruining the user experience.

For details about how the socket is initially created, read my post, [Sockets in the Linux Kernel](https://bmixonba.github.io/2025-05-22-Sockets-in-the-Linux-Kernel/)

# The Attack

The client-side attack works as follows. Assume that a target, `T`, is connected to a VPN server, `V`, and has an ESTABLISHED TCP
connection to a website, `W`. `T` sends data to `W` by issuing `write`s (`send` or `sendmsg`) to a socket, `_s_`.

The attacker spoofs a packet from the website to the target that matches this 
ESTABLISHED connection. In particular, the link-layer header has a destination MAC address equal to MAC
address of the WiFI interface the cl

# Initialization 

When Linux, and more specifically Android, first boots, it initializes a number
of critical systems. For networking, this includes the interfaces (e.g.,
network cards and mobile data modems), the network stack (TCP/IP), the
Netfilter framework, SELinux, and adding policy-routing rules.

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
The function that will actually handle packet reception is `emac_napi_rtx`.

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

```c
static int selinux_tun_dev_attach(struct sock *sk, void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	struct sk_security_struct *sksec = selinux_sock(sk);

```
Figure X. SELinux tun-based hook. Located at [`security/selinux/hooks.c`](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L5680).

## Network Stack 

When Linux is booted, its Networking subsystem registers all of the supported protocols. For 
the TCP/IP and UDP/IP stacks, the `inet_init` function in [`af_inet`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L1890) is responsible for this. The
kernel provides a framework for network layer protocols to register a packet
processing function using the `packet_type` data structure. `af_inet` defines
the `ip_packet_type` object and registers it with in `inet_init` with a call to
`dev_add_pack` shown below. 

```c
.
static struct packet_type ip_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = ip_rcv,
	.list_func = ip_list_rcv,
};
.
.
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
.
.
	dev_add_pack(&ip_packet_type);
.


}
```
Figure. Network stack initialization in [`af_inet`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L1890).

## Netfilter

The netfilter framework registers a numbre of critical subsystems to be initialized when Linux first boots. The conntrack
module, the SElinux policy.

```c
.
MODULE_PARM_DESC(enable_hooks, "Always enable conntrack hooks");
.
.
module_init(nf_conntrack_standalone_init);
module_exit(nf_conntrack_standalone_fini);
```
Figure. Conntrack module registration and initailzation. Located at [``](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_standalone.c#L948).

Because Linux supports network namespaces and multiple `networks`, which Android makes extensive use of, conntrack is initialized with a pernet conntrack module.

```c
static struct pernet_operations nf_conntrack_net_ops = {
	.init		= nf_conntrack_pernet_init,
	.exit_batch	= nf_conntrack_pernet_exit,
	.id		= &nf_conntrack_net_id,
	.size = sizeof(struct nf_conntrack_net),
};

static int __init nf_conntrack_standalone_init(void)
{
	int ret = nf_conntrack_init_start();
.
	ret = register_pernet_subsys(&nf_conntrack_net_ops);
.
}
```
Figure. Conntrack initialization and registration with Kernel and Netfilter. Located at [``](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_standalone.c#L1182).

SELinux is initialized early in the boot process so that it is able to properly
label all processes and objects when they are created. Per

```c
/* SELinux requires early initialization in order to label
   all processes and objects when they are created. */
DEFINE_LSM(selinux) = {
	.name = "selinux",
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &selinux_enabled_boot,
	.blobs = &selinux_blob_sizes,
	.init = selinux_init,
};

#if defined(CONFIG_NETFILTER)
static const struct nf_hook_ops selinux_nf_ops[] = {
	{
		.hook =		selinux_ip_postroute,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_POST_ROUTING,
		.priority =	NF_IP_PRI_SELINUX_LAST,
	},
	{
		.hook =		selinux_ip_forward,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_FORWARD,
		.priority =	NF_IP_PRI_SELINUX_FIRST,
	},
	{
		.hook =		selinux_ip_output,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP_PRI_SELINUX_FIRST,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook =		selinux_ip_postroute,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_POST_ROUTING,
		.priority =	NF_IP6_PRI_SELINUX_LAST,
	},
	{
		.hook =		selinux_ip_forward,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_FORWARD,
		.priority =	NF_IP6_PRI_SELINUX_FIRST,
	},
	{
		.hook =		selinux_ip_output,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP6_PRI_SELINUX_FIRST,
	},
#endif	/* IPV6 */
};

static int __net_init selinux_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, selinux_nf_ops,
				     ARRAY_SIZE(selinux_nf_ops));
}
```
Figure. SELinux initialization data structure and registration with Netfitler. Located at [`security/selinux/hooks.c`](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L7562).

SELinux registers several hooks with Netfilter. These hooks are registered with
the `NF_INET_POSTROUTING`, `NF_INET_FORWARD`, and `NF_INET_LOCAL_OUT` hooks.
The code that registers SELinux with the Kernel by calling `__initcall`.

```c
static int __init selinux_nf_ip_init(void)
{
	int err;

	if (!selinux_enabled_boot)
		return 0;

	pr_debug("SELinux:  Registering netfilter hooks\n");

	err = register_pernet_subsys(&selinux_net_ops);
	if (err)
		panic("SELinux: register_pernet_subsys: error %d\n", err);

	return 0;
}
__initcall(selinux_nf_ip_init);
#endif /* CONFIG_NETFILTER */
```
Figure. SELinux module registration and initailzation. Located at [`security/selinux/hooks.c`](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L7631).


```c
static unsigned int selinux_ip_postroute(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
.
.
	sk = skb_to_full_sk(skb);
#ifdef CONFIG_XFRM
	/* If skb->dst->xfrm is non-NULL then the packet is undergoing an IPsec
	 * packet transformation so allow the packet to pass without any checks
	 * since we'll have another chance to perform access control checks
	 * when the packet is on it's final way out.
	 * NOTE: there appear to be some IPv6 multicast cases where skb->dst
	 *       is NULL, in this case go ahead and apply access control.
	 * NOTE: if this is a local socket (skb->sk != NULL) that is in the
	 *       TCP listening state we cannot wait until the XFRM processing
	 *       is done as we will miss out on the SA label if we do;
	 *       unfortunately, this means more work, but it is only once per
	 *       connection. */
	if (skb_dst(skb) != NULL && skb_dst(skb)->xfrm != NULL &&
	    !(sk && sk_listener(sk)))
		return NF_ACCEPT;
#endif
.
.
.
	} else if (sk_listener(sk)) {
		/* Locally generated packet but the associated socket is in the
		 * listening state which means this is a SYN-ACK packet.  In
		 * this particular case the correct security label is assigned
		 * to the connection/request_sock but unfortunately we can't
		 * query the request_sock as it isn't queued on the parent
		 * socket until after the SYN-ACK packet is sent; the only
		 * viable choice is to regenerate the label like we do in
		 * selinux_inet_conn_request().  See also selinux_ip_output()
		 * for similar problems. */
		u32 skb_sid;
		struct sk_security_struct *sksec;

		sksec = selinux_sock(sk);
		if (selinux_skb_peerlbl_sid(skb, family, &skb_sid))
			return NF_DROP;
.
}
```
Figure. Postrouting hook for SELinux. Details at [`security/selinux/hooks.c`](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L5846).

`OPEN QUESTIONS`: 
1. The `sk` is null when the `PREROUTING` hook is called but is the `sk` for `skb` null at post routing?
2. Is XFRM compiled for the Android kernel?
3. How can SELinux determine whether the packet is to be forwarded? I'm
   guessing since this is happening at POSTROUTING, then the decsion about
   whether its destined for the local machine or forwarded is already determined.
4. Check if SECMARK is enabled on Android.


The previous sections covered the various components that Linux intializes once
its booted. The next section describes the journey of the packet as it transitions
from electrons `on the wire` to the `skb` representation in the kernel.

## Policy-routing rules

Android adds policy-routing rules to properly route packets from the processes to the tunnel before
sending them to the VPN server. The following routing rules we taken from a root Android device
I was using for analysis. To list the policy routing rules, use the `ip rule` command from
the `iproute2` framework.

```bash
lynx:/ # ip rule
0:	from all lookup local 
10000:	from all fwmark 0xc0000/0xd0000 lookup legacy_system 
11000:	from all iif lo oif dummy0 uidrange 0-0 lookup dummy0 
11000:	from all iif lo oif rmnet1 uidrange 0-0 lookup rmnet1 
11000:	from all iif lo oif wlan0 uidrange 0-0 lookup wlan0 
12000:	from all iif tun1 lookup local_network 
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 0-10307 lookup tun1 
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 10309-20307 lookup tun1 
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 20309-99999 lookup tun1 
13000:	from all fwmark 0xc0248/0xcffff lookup tun1 
14000:	from all fwmark 0x0/0x20000 iif lo uidrange 1-10307 prohibit
14000:	from all fwmark 0x0/0x20000 iif lo uidrange 10309-20307 prohibit
14000:	from all fwmark 0x0/0x20000 iif lo uidrange 20309-99999 prohibit
15040:	from all fwmark 0x10246/0x1ffff iif lo uidrange 10179-10179 lookup wlan0 
16000:	from all fwmark 0x10063/0x1ffff iif lo lookup local_network 
16000:	from all fwmark 0xd0064/0xdffff iif lo lookup rmnet1 
16000:	from all fwmark 0x10246/0x1ffff iif lo lookup wlan0 
16000:	from all fwmark 0x10248/0x1ffff iif lo uidrange 0-10307 lookup tun1 
16000:	from all fwmark 0x10248/0x1ffff iif lo uidrange 10309-20307 lookup tun1 
16000:	from all fwmark 0x10248/0x1ffff iif lo uidrange 20309-99999 lookup tun1 
16000:	from all fwmark 0x10248/0x1ffff iif lo uidrange 0-0 lookup tun1 
17000:	from all iif lo oif dummy0 lookup dummy0 
17000:	from all fwmark 0xc0000/0xc0000 iif lo oif rmnet1 lookup rmnet1 
17000:	from all iif lo oif wlan0 lookup wlan0 
17000:	from all iif lo oif tun1 uidrange 0-10307 lookup tun1 
17000:	from all iif lo oif tun1 uidrange 10309-20307 lookup tun1 
17000:	from all iif lo oif tun1 uidrange 20309-99999 lookup tun1 
18000:	from all fwmark 0x0/0x10000 lookup legacy_system 
19000:	from all fwmark 0x0/0x10000 lookup legacy_network 
20000:	from all fwmark 0x0/0x10000 lookup local_network 
22040:	from all fwmark 0x246/0x1ffff iif lo uidrange 10179-10179 lookup wlan0 
23000:	from all fwmark 0x246/0x1ffff iif lo lookup wlan0 
25000:	from all fwmark 0x0/0x10000 iif lo uidrange 10179-10179 lookup wlan0_local 
26000:	from all fwmark 0x0/0x10000 iif lo lookup wlan0_local 
28000:	from all fwmark 0x248/0xffff lookup wlan0 
29040:	from all fwmark 0x0/0xffff iif lo uidrange 10179-10179 lookup wlan0 
31000:	from all fwmark 0x0/0xffff iif lo lookup wlan0 
32000:	from all unreachable
```
Figure. Android policy routing rules.

Lets explain what these rules mean. Take the 5th rule from the top. The general structure
of in policy routing rule is a follows: `[priority] [filter] [target]`.

```bash
11000:  from all iif lo oif wlan0 uidrange 0-0 lookup wlan0
```
Figure X. initial rule for `wlan0` interface.

The following list explains each component of the rule:

1. `11000` - `priority`: The priority of the rule. 
2. `from all` - `filter`: This says match on any incoming interface. 
3. `iif lo`- `filter`: This says match only locally generated traffic, not fowarded traffic.
4. `oif wlan0` - `filter`: This says match only traffic destined for the `wlan0` interface.
5. `uidrange 0-0` - `filter`: This says, match the uids in the specified range, so only match the root uid.
6. `lookup wlan0` - `filter`: This says, lookup the route on the `wlan0` network.

Policy routing rules can be added using the [`iproute2`](https://github.com/iproute2/iproute2/tree/main) framework.
In a future post, I plan to write about the internals of this tool. For now, it's interesting to note
that it uses the `netlink` framework and `fib` objects to add rules.

### Policy-routing in Android

TODO: Add info about when and how Android adds its policy routing rules.


# Packet Reception

After a machine sends a packet, the digital represetion is transformed into an
analogue (electircal or luminal) signal that travels at some constant times the
`c` (the speed of light), `k*c`. It eventually reaches youe device's network
interface card, which acts as an `ADC` or analogue-to-digital-convert where it
is convered to a digital signal and stored in the network card's memory. The
card then raises an interupt with the CPU of your device which induces the Kernel
to execute some interrupt request handler to process the packet. (I think?)

This is the Link layer and is the interface from analogue to digital signals.
The link layer then processes the packet and passes it up to the network layer
which further processes the packet, either forwarding it or passing it further
up to the transport layer, consuming it.

## Link Layer

Depending on which interface receives the packet, either the Wifi card, mobile data modem, or 
tun interface, a receive function is invoked. 

### WiFi

As previously described in the initialization section, the Qualcomm driver
registers a number of functions with the kernel, including the `emac_napi_rtx`
function. This function is called after the the kernel to handle the interupt
induced on the CPU by the network card.

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

This is just a wrapper for `emac_mac_rx_process`, which does the actual packet
processes and calls, e.g., the `af_inet` (TCP/IP) stack.  Before this happens a
lot of sanity checks are performed. For the Qualcomm driver, the generic
receiption offloading (GRO) framework ised used instead of calling the `ip_rcv`
routine directly every time an interupt from the network card is raised.

```c
/* Process receive event */
void emac_mac_rx_process(struct emac_adapter *adpt, struct emac_rx_queue *rx_q,
			 int *num_pkts, int max_pkts)
{
.
.
	do {
.
		if (likely(RRD_NOR(&rrd) == 1)) {
			/* good receive */
			rfbuf = GET_RFD_BUFFER(rx_q, RRD_SI(&rrd));
			dma_unmap_single(adpt->netdev->dev.parent,
					 rfbuf->dma_addr, rfbuf->length,
					 DMA_FROM_DEVICE);
			rfbuf->dma_addr = 0;
			skb = rfbuf->skb;
.
		skb_put(skb, RRD_PKT_SIZE(&rrd) - ETH_FCS_LEN);
		skb->dev = netdev;
		skb->protocol = eth_type_trans(skb, skb->dev);
.
		emac_receive_skb(rx_q, skb, (u16)RRD_CVALN_TAG(&rrd),
				 (bool)RRD_CVTAG(&rrd));
		(*num_pkts)++;
	} while (*num_pkts < max_pkts);
.
}
```
Figure X. Code to pull a packet from the Qualcomm `rx` queue and call, e.g., `af_inet`, in [`drivers/net/qualcomm/emac-emac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac-mac.c#L1087).


The driver sets up the `skb` such as adding the device driver the `skb. It then
calls `napi_gro_receive`. GRO is resonsible for aggregating packets for the
same stream before delivering them to the network stack. 


```c
/* Push the received skb to upper layers */
static void emac_receive_skb(struct emac_rx_queue *rx_q,
			     struct sk_buff *skb,
			     u16 vlan_tag, bool vlan_flag)
{
	if (vlan_flag) {
		u16 vlan;

		EMAC_TAG_TO_VLAN(vlan_tag, vlan);
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan);
	}

	napi_gro_receive(&rx_q->napi, skb);
}
```
Figure X. Qualcomm card delivering `skb` to upper layers _via_ NAPI. In [`drivers/net/qualcomm/emac/emac-mac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac-mac.c#L1071).

Like `NAPI`, Generic Receiver Offload (GRO for short) is a technique the Linux
kernel uses to aggregate groups of packets, process, and pass them up the
network stack at once instead of processing every single packet as it is
received. For more information on GRO, check out the article by
[DPDK](https://doc.dpdk.org/guides/prog_guide/generic_receive_offload_lib.html).

Like all of the other code, `napi_gro_receive` is a wrapper that does bookkeeping before calling 
`gro_receive_skb`, which calls `dev_gro_receive`.

```c
gro_result_t gro_receive_skb(struct gro_node *gro, struct sk_buff *skb)
{
	gro_result_t ret;

	__skb_mark_napi_id(skb, gro);
	trace_napi_gro_receive_entry(skb);

	skb_gro_reset_offset(skb, 0);

	ret = gro_skb_finish(gro, skb, dev_gro_receive(gro, skb));
	trace_napi_gro_receive_exit(ret);

	return ret;
}
```
Figure X. GRO receive function calls `dev_gro_receive` to pass the `skb` up the network
stack for packet aggregation. More details can be found at [`net/core/gro.c`](https://github.com/torvalds/linux/blob/master/net/core/gro.c#L622).



```c
static enum gro_result dev_gro_receive(struct gro_node *gro,
				       struct sk_buff *skb)
{
	u32 bucket = skb_get_hash_raw(skb) & (GRO_HASH_BUCKETS - 1);
.
.

	pp = INDIRECT_CALL_INET(ptype->callbacks.gro_receive,
				ipv6_gro_receive, inet_gro_receive,
				&gro_list->list, skb);
.
.
}
```
Figure. GRO calling the `af_inet` packet reception code `inet_gro_receive` for IPv4 or `ipv6_gro_receive` for IPv6. 
More details at [`net/core/gro.c#L460`](https://github.com/torvalds/linux/blob/master/net/core/gro.c#L460).

The `gro_*` functions for IP and TCP/UDP are used to aggregate fragmented (and segmented?) packets, but do not
make any routing decisions.


Once the packet streams have been collated, `gro_receive_skb` calls `gro_receive_finish`.

```c
static gro_result_t gro_skb_finish(struct gro_node *gro, struct sk_buff *skb,
				   gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
		gro_normal_one(gro, skb, 1);
		break;
```
Figure. `gro_skb_finish` is called once GRO has aggregated a stream of packets. Details at [`net/core/gro.c`](https://github.com/torvalds/linux/blob/master/net/core/gro.c#L596).

```c
/* Queue one GRO_NORMAL SKB up for list processing. If batch size exceeded,
 * pass the whole batch up to the stack.
 */
static inline void gro_normal_one(struct gro_node *gro, struct sk_buff *skb,
				  int segs)
{
	list_add_tail(&skb->list, &gro->rx_list);
	gro->rx_count += segs;
	if (gro->rx_count >= READ_ONCE(net_hotdata.gro_normal_batch))
		gro_normal_list(gro);
}
```
Figure. `gro_normal_one` is used to pass the aggregated packets up the stack. Details at [`include/net/gro.h`](https://github.com/torvalds/linux/blob/master/include/net/gro.h#L540).

More boilerplate and indirection are called, but we are finally getting to something that resembles `ip_rcv`.

```c
/* Pass the currently batched GRO_NORMAL SKBs up to the stack. */
static inline void gro_normal_list(struct gro_node *gro)
{
	if (!gro->rx_count)
		return;
	netif_receive_skb_list_internal(&gro->rx_list);
	INIT_LIST_HEAD(&gro->rx_list);
	gro->rx_count = 0;
}

```

The function `netif_receive_skb_list_internal` while boiler plate, is at least out of the GRO could
and closer to an IP receive routine, which is what we need for packet routing.


```c
void netif_receive_skb_list_internal(struct list_head *head)
{
	struct sk_buff *skb, *next;
.
.

	__netif_receive_skb_list(head);
	rcu_read_unlock();
}
```
Figure. Device receive function interface. This function recieves a list of `skb`s from GRO
and passes them up the network stack.

```c
static void __netif_receive_skb_list(struct list_head *head)
{
	unsigned long noreclaim_flag = 0;
	struct sk_buff *skb, *next;
	bool pfmemalloc = false; /* Is current sublist PF_MEMALLOC? */
.

	list_for_each_entry_safe(skb, next, head, list) {
		if ((sk_memalloc_socks() && skb_pfmemalloc(skb)) != pfmemalloc) {
.
			if (!list_empty(&sublist))
				__netif_receive_skb_list_core(&sublist, pfmemalloc);
.
```
Figure X. More indirection to get to Network stack. Mostly book keeping for memory
and to process the list of GRO packets. Located in [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L6005).

```c
static void __netif_receive_skb_list_core(struct list_head *head, bool pfmemalloc)
{
.
.
	list_for_each_entry_safe(skb, next, head, list) {
		struct net_device *orig_dev = skb->dev;
.
		__netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
.
	/* dispatch final sublist */
	__netif_receive_skb_list_ptype(&sublist, pt_curr, od_curr);

.
.
}
```
Figure X. Located in [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L5939)


```c
static inline void __netif_receive_skb_list_ptype(struct list_head *head,
						  struct packet_type *pt_prev,
						  struct net_device *orig_dev)
{
	struct sk_buff *skb, *next;

	if (!pt_prev)
		return;
	if (list_empty(head))
		return;
	if (pt_prev->list_func != NULL)
		INDIRECT_CALL_INET(pt_prev->list_func, ipv6_list_rcv,
				   ip_list_rcv, head, pt_prev, orig_dev);
	else
		list_for_each_entry_safe(skb, next, head, list) {
			skb_list_del_init(skb);
			pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
		}
}
```
Figure X. Located at [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L5919) 

At last, we have reach the final layer of indirection between the generic
packet reception code and the IP stack. In if clause, the `INDIRECT_CALL_INET`
is a macro that calls either
[`ipv6_list_rcv`](https://github.com/torvalds/linux/blob/master/net/ipv6/ip6_input.c#L323)
for IPv6 or
[`ip_list_rcv`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L639)
for IPv4. This clause is executed when the network layer (e.g., IPv4 or v6)
registered a processing function for lists of packets (e.g., fragments).
Otherwise, `pt_prev->func` is going to be either
[`ip_rcv`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L558)
or
[`ipv6_rcv`](https://github.com/torvalds/linux/blob/master/net/ipv6/ip6_input.c#L302).

In the `Network Layer` section, I cover how the packet is delivered to the `af_inet` module.


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

After the packets have been aggregated and passed up the network stack through
GRO, the `ip_rcv` function is called. Recall that it is not called directly,
but through the `ip_packet_type` registered with the kernel. 

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
Figure X. The receive routine registered with the kernel. Details at [`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#558)

The `ip_rcv_core` function is primarly used to get the `skb` ready for processing further up the network stack. This
includes removing padding that may have been added by the receiving network card, making sure
the header length and checksum are correct, and setting the transport layer header.


```c
/*
 * 	Main IP Receive routine.
 */
static struct sk_buff *ip_rcv_core(struct sk_buff *skb, struct net *net)
{
.
.
	iph = ip_hdr(skb);
	skb->transport_header = skb->network_header + iph->ihl*4;
.
}
```
Figure X. `ip_rcv_core` is mainly used for book keeping and sanity checking the packet. Details at `net/ip_input.c`(https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L454)


After the `skb` is confirmed to be legit and the appropriate book keeping has
been done (e.g., `transport_header` pointer for the `skb` has been updated),
`ip_rcv` calls `ip_rcv_finish` as a function to be called after the rules in
`Netfilter`'s `PREROUTING` hook have been executed. From what I can tell,
unlike the classic `Netfilter` diagram that shows the `PREROUTING` chains being
called in the Link Layer (Bridge layer in the diagram), it is actually called for the first
time just before the IP layer works its magic.


```c
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}

```
Figre X. Located at (`include/linux/netfilter.h`)[https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h#L307].

As always `NF_HOOK` is a wrapper for the underlying `nf_hook` function that
handles the return codes for the Netfilter hooks and ultimately calls
`ip_rcv_finish` if the packet is allowed to `PASS`.

Most of the parameters to `nf_hook` are self explanetory. First, `pf` which is
`AF_INET` in the case of IP. The `PRE_ROUTING` hook indicates that packet
processing occurs before any routing decisions are made. The `net` data
structure is interesting because, from what I understand, this object
represents network name spaces. Network name spaces make it possible to
implement different routing tables across multiple interfaces and implement the
granular control of the `skb`, aka, policy-routing.

The `indev` is the Qualcomm device that received the packet while the `outdev` is
currently `NULL`. This will be assigned later when the routing table is looked up.




#### `Questions`
1. Where and when is the device's network name space `dev` initialized.
2. MAYBE ANSWERED: What are the values of `indev` and `outdev`? 

```c

/**
 *	nf_hook - call a netfilter hook
 *
 *	Returns 1 if the hook has allowed the packet to pass.  The function
 *	okfn must be invoked by the caller in this case.  Any other return
 *	value indicates the packet has been consumed by the hook.
 */
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
.
	rcu_read_lock();
	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
.
.
	if (hook_head) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, pf, indev, outdev,
				   sk, net, okfn);

		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();

	return ret;
}
```
Figure. Netfilter wrapper function to determine which hook to execute. Details at [`include/linux/netfilter.h`](https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h#L223).

The `nf_hook_state_init` function just takes all the parameters passed to it
and assigns them to members of the `nf_hook_state` struct.  The real work is
performed by `nf_hook_slow`, which loops through the Netfilter rules registered
with the particular address family `AF_INET` and hook `PREROUTING`.

```c
/* Returns 1 if okfn() needs to be executed by the caller,
 * -EPERM for NF_DROP, 0 otherwise.  Caller must hold rcu_read_lock. */
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
		 const struct nf_hook_entries *e, unsigned int s)
{
	unsigned int verdict;
	int ret;

	for (; s < e->num_hook_entries; s++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			break;
}
```
Figure X. Routine to loop through Netfilter rules. Details at [`net/netfilter/core.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/core.c#L617).

Recall that Netfilter initializes its subsystem early. This includes the
`conntrack` module, which is always registered, and `SELinux` in the case of
Android.

`TODO:`
1. Add some hooks related to PREROUTING.
2. Maybe talk about the hook registration process?

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



```c
static int ip_rcv_finish_core(struct net *net,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint)
{
	const struct iphdr *iph = ip_hdr(skb);
	int err, drop_reason;
	struct rtable *rt;
.
.
	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_valid_dst(skb)) {
		drop_reason = ip_route_input_noref(skb, iph->daddr, iph->saddr,
						   ip4h_dscp(iph), dev);
		if (unlikely(drop_reason))
			goto drop_error;
		drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
.

#ifdef CONFIG_IP_ROUTE_CLASSID
.
.
	rt = skb_rtable(skb);

	return NET_RX_SUCCESS;


```
Figure. Located at [`net/ipv4/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L317).


```c
enum skb_drop_reason ip_route_input_noref(struct sk_buff *skb, __be32 daddr,
					  __be32 saddr, dscp_t dscp,
					  struct net_device *dev)
{
	enum skb_drop_reason reason;
	struct fib_result res;

	rcu_read_lock();
	reason = ip_route_input_rcu(skb, daddr, saddr, dscp, dev, &res);
	rcu_read_unlock();

	return reason;
}
EXPORT_SYMBOL(ip_route_input_noref);

```
Figure. Located at [``](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2526).

```c

```
Figure. `ip_route_input_rcu`. Located at [`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2474).

```c
/*
 *	NOTE. We drop all the packets that has local source
 *	addresses, because every properly looped back packet
 *	must have correct destination already attached by output routine.
 *	Changes in the enforced policies must be applied also to
 *	ip_route_use_hint().
 *
 *	Such approach solves two big problems:
 *	1. Not simplex devices are handled properly.
 *	2. IP spoofing attempts are filtered with 100% of guarantee.
 *	called with rcu_read_lock()
 */
static enum skb_drop_reason
ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
		    dscp_t dscp, struct net_device *dev,
		    struct fib_result *res)
{
	enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
	struct in_device *in_dev = __in_dev_get_rcu(dev);
	struct flow_keys *flkeys = NULL, _flkeys;
	struct net    *net = dev_net(dev);
	struct ip_tunnel_info *tun_info;
.
.
	/*
	 *	Now we are ready to route packet.
	 */
.
	fl4.flowi4_mark = skb->mark;

	fl4.flowi4_uid = sock_net_uid(net, NULL);
.
        err = fib_lookup(net, &fl4, res, 0);
	if (err != 0) {
		if (!IN_DEV_FORWARD(in_dev))
.
.
	err = -EINVAL;
	if (res->type == RTN_LOCAL) {
		reason = fib_validate_source_reason(skb, saddr, daddr, dscp,
						    0, dev, in_dev, &itag);
		if (reason)
			goto martian_source;
		goto local_input;
	}

	if (!IN_DEV_FORWARD(in_dev)) {
		err = -EHOSTUNREACH;
		goto no_route;
	}
	if (res->type != RTN_UNICAST) {
		reason = SKB_DROP_REASON_IP_INVALID_DEST;
		goto martian_destination;
	}

make_route:
	reason = ip_mkroute_input(skb, res, in_dev, daddr, saddr, dscp,
				  flkeys);
}
```
Figure `ip_route_input_slow` in [route.c](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2908)

When `ip_route_input_slow` runs, it retrives the `in_device`, and the associated `net` (network)
with the incoming `net_device`. `in_device` is a pointer to the device that
received the packet, `net` is the network associated with the device (recall that in Linux, 
multiple networks and associated routing tables can be defined). `ip_route_input_slow` uses
a `flow_keys` object `flkeys` to look up the incoming route for the `skb`. The `flkeys` 
contains the socket mark `mark` and the `uid` of the associated `net` object.

Question:
1. When is the `skb->mark` field set on the incoming path?
2. 

The call to `fib_lookup` finds the correct route for the incoming packet. `fib_lookup` has two definitions, one for
when the kernel supports only one routing table, and one for when multiple tables are available.

```c
static inline int fib_lookup(struct net *net, struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	flags |= FIB_LOOKUP_NOREF;
	if (net->ipv4.fib_has_custom_rules)
		return __fib_lookup(net, flp, res, flags);

	rcu_read_lock();

	res->tclassid = 0;

	tb = rcu_dereference_rtnl(net->ipv4.fib_main);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags);

	if (!err)
		goto out;

	tb = rcu_dereference_rtnl(net->ipv4.fib_default);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags);

out:
	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}
```
Figure X. `fig_lookup` for multiple tables [374](https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L374).


When multiple tables are defined, the routing code calls into `__fib_lookup` in
[`fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L108).

```c
int __fib_lookup(struct net *net, struct flowi4 *flp,
		 struct fib_result *res, unsigned int flags)
{
.
	err = fib_rules_lookup(net->ipv4.rules_ops, flowi4_to_flowi(flp), 0, &arg);

}

```
Figure X. Located at [``](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L83).


```c

int fib_rules_lookup(struct fib_rules_ops *ops, struct flowi *fl,
		     int flags, struct fib_lookup_arg *arg)
{
.
	list_for_each_entry_rcu(rule, &ops->rules_list, list) {
jumped:
		if (!fib_rule_match(rule, ops, fl, flags, arg))
			continue;
.
.
		if (!fib_rule_match(rule, ops, fl, flags, arg))
			continue;
					       fib6_rule_action,
					       fib4_rule_action,
					       rule, fl, flags, arg);

}
```
Figure X. in `fig_rules.c` Line [108](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L108)


```c
static int fib_rule_match(struct fib_rule *rule, struct fib_rules_ops *ops,
			  struct flowi *fl, int flags,
			  struct fib_lookup_arg *arg)
{
	int iifindex, oifindex, ret = 0;
.

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
	return (rule->flags & FIB_RULE_INVERT) ? !ret : ret;
}
```
Figure. Routine for policy-based routing decisions. Located at [`net/core/fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/core/fib_rules.c#L278).

The `fib_rule_match` function is the primary function for making policy-routing decisions. Various 
pieces of information from the `flowi` (ie., `flow_keys`) object are compared against the `struct fib_rule rule`.
In the case of VPNs in Android, XXX.



```c
INDIRECT_CALLABLE_SCOPE int fib4_rule_action(struct fib_rule *rule,
					     struct flowi *flp, int flags,
					     struct fib_lookup_arg *arg)
{
	int err = -EAGAIN;
	struct fib_table *tbl;
	u32 tb_id;
.
.
	rcu_read_lock();

	tb_id = fib_rule_get_table(rule, arg);
	tbl = fib_get_table(rule->fr_net, tb_id);
	if (tbl)
		err = fib_table_lookup(tbl, &flp->u.ip4,
				       (struct fib_result *)arg->result,
				       arg->flags);

	rcu_read_unlock();
	return err;
}
```
Figure. Located at [`net/ipv4/fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L110).

The routing table for the specific network is found found by calling to `fib_get_table` and passing it `rule->fr_net` and the
table id.

```c
* caller must hold either rtnl or rcu read lock */
struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist,
				 lockdep_rtnl_is_held()) {
		if (tb->tb_id == id)
			return tb;
	}
	return NULL;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */
```
Figure. `fib_get_table` when Linux is configured to support multiple routing tables. Located at [``](https://github.com/torvalds/linux/blob/b1427432d3b656fac71b3f42824ff4aea3c9f93b/net/ipv4/fib_frontend.c#L111).





Once the route has been stored in `fib_result`, the kernel checks whether the packet should be routed to this machine,
`res-type==RTN_LOCAL`, fowarded, or dropped, because either a route doesn't exist or because the packet has a
martian destination.

When the packet is destined for the local box, `fib_validate_source` is called to ensure that the source address
is valid. Interestingly, in the case of IPSec, source address validation, i.e., `rp_filter` is ignored. 

```c
/* Ignore rp_filter for packets protected by IPsec. */
int fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
			dscp_t dscp, int oif, struct net_device *dev,
			struct in_device *idev, u32 *itag)
{
	int r = secpath_exists(skb) ? 0 : IN_DEV_RPFILTER(idev);
	struct net *net = dev_net(dev);

	if (!r && !fib_num_tclassid_users(net) &&
	    (dev->ifindex != oif || !IN_DEV_TX_REDIRECTS(idev))) {
		if (IN_DEV_ACCEPT_LOCAL(idev))
			goto ok;
		/* with custom local routes in place, checking local addresses
		 * only will be too optimistic, with custom rules, checking
		 * local addresses only can be too strict, e.g. due to vrf
		 */
		if (net->ipv4.fib_has_custom_local_routes ||
		    fib4_has_custom_rules(net))
			goto full_check;
.
.
ok:
		*itag = 0;
		return 0;
	}
full_check:
	return __fib_validate_source(skb, src, dst, dscp, oif, dev, r, idev,
				     itag);
}
```
Figure X. Source address validation for locally destined packets. Located at [`net/ipv4/fib_frontend.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c#L428.).


The validation is performed by `__fib_validate_source`.
```c
static int __fib_validate_source(struct sk_buff *skb, __be32 src, __be32 dst,
				 dscp_t dscp, int oif, struct net_device *dev,
				 int rpf, struct in_device *idev, u32 *itag)
{
	struct net *net = dev_net(dev);
	enum skb_drop_reason reason;
	struct flow_keys flkeys;
	int ret, no_addr;
	struct fib_result res;
	struct flowi4 fl4;
	bool dev_match;

	fl4.flowi4_oif = 0;
	fl4.flowi4_l3mdev = l3mdev_master_ifindex_rcu(dev);
	fl4.flowi4_iif = oif ? : LOOPBACK_IFINDEX;
	fl4.daddr = src;
	fl4.saddr = dst;
	fl4.flowi4_tos = inet_dscp_to_dsfield(dscp);
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	fl4.flowi4_tun_key.tun_id = 0;
	fl4.flowi4_flags = 0;
	fl4.flowi4_uid = sock_net_uid(net, NULL);
	fl4.flowi4_multipath_hash = 0;
.
.

}
```
Figure X. Located at [`fib_frontend.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c#L344).


`ip_mkroute_input` is called.
```c

static enum skb_drop_reason
ip_mkroute_input(struct sk_buff *skb, struct fib_result *res,
		 struct in_device *in_dev, __be32 daddr,
		 __be32 saddr, dscp_t dscp, struct flow_keys *hkeys)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (res->fi && fib_info_num_path(res->fi) > 1) {
		int h = fib_multipath_hash(res->fi->fib_net, NULL, skb, hkeys);

		fib_select_multipath(res, h);
		IPCB(skb)->flags |= IPSKB_MULTIPATH;
	}
#endif

	/* create a routing cache entry */
	return __mkroute_input(skb, res, in_dev, daddr, saddr, dscp);
}
```
Figure X. Call to `ip_mkroute_input` with the `fib_result` passed. Located at[`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2149).

TODO: Does android have multipath configured?


```c
/* called in rcu_read_lock() section */
static enum skb_drop_reason
__mkroute_input(struct sk_buff *skb, const struct fib_result *res,
		struct in_device *in_dev, __be32 daddr,
		__be32 saddr, dscp_t dscp)
{
	enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
	struct fib_nh_common *nhc = FIB_RES_NHC(*res);
	struct net_device *dev = nhc->nhc_dev;
.
.
	rth->dst.input = ip_forward;

	rt_set_nexthop(rth, daddr, res, fnhe, res->fi, res->type, itag,
		       do_cache);
	lwtunnel_set_redirect(&rth->dst);
	skb_dst_set(skb, &rth->dst);
out:
	reason = SKB_NOT_DROPPED_YET;
cleanup:
	return reason;
}
```
Figure X. Located at [``](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L1797).

`TODO`
1. Are classids defind in Android?

![Netfilter calling points for different tables and default chains.](./imgs/Netfilter-packet-flow.png)
(Original source at [Wikipedia](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg))


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
struct rtable *rt_dst_alloc(struct net_device *dev,
			    unsigned int flags, u16 type,
			    bool noxfrm)

			rt->dst.input = ip_local_deliver;

```


## Client: Local to Remote 


### Netfilter POSTROUTING

```c
static unsigned int selinux_ip_postroute(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
.
.
#ifdef CONFIG_XFRM
	/* If skb->dst->xfrm is non-NULL then the packet is undergoing an IPsec
	 * packet transformation so allow the packet to pass without any checks
	 * since we'll have another chance to perform access control checks
	 * when the packet is on it's final way out.
	 * NOTE: there appear to be some IPv6 multicast cases where skb->dst
	 *       is NULL, in this case go ahead and apply access control.
	 * NOTE: if this is a local socket (skb->sk != NULL) that is in the
	 *       TCP listening state we cannot wait until the XFRM processing
	 *       is done as we will miss out on the SA label if we do;
	 *       unfortunately, this means more work, but it is only once per
	 *       connection. */
	if (skb_dst(skb) != NULL && skb_dst(skb)->xfrm != NULL &&
	    !(sk && sk_listener(sk)))
		return NF_ACCEPT;
#endif
.
	} else if (sk_listener(sk)) {
		/* Locally generated packet but the associated socket is in the
		 * listening state which means this is a SYN-ACK packet.  In
		 * this particular case the correct security label is assigned
		 * to the connection/request_sock but unfortunately we can't
		 * query the request_sock as it isn't queued on the parent
		 * socket until after the SYN-ACK packet is sent; the only
		 * viable choice is to regenerate the label like we do in
		 * selinux_inet_conn_request().  See also selinux_ip_output()
		 * for similar problems. */
		u32 skb_sid;
.
		/* At this point, if the returned skb peerlbl is SECSID_NULL
		 * and the packet has been through at least one XFRM
		 * transformation then we must be dealing with the "final"
		 * form of labeled IPsec packet; since we've already applied
		 * all of our access controls on this packet we can safely
		 * pass the packet. */
}
```
Figure. SELinux hook registered with the POSTROUTING hook. Location [`security/selinux/hooks.c`](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L5905).

```c
static unsigned int selinux_ip_output(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct sock *sk;
	u32 sid;

	if (!netlbl_enabled())
		return NF_ACCEPT;
```
Figure X. SELinux `OUT` hook.[``](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c#L5905).


## Router: Remote to Remote 
