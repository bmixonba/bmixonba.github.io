# Initialization

When Linux, and more specifically Android, first boots, it initializes
a number of critical systems. For networking, this includes the
interfaces (e.g., network cards and mobile data modems), the network
stack (TCP/IP), the Netfilter framework, SELinux, and adding
policy-routing rules.

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


