# How Linux Routes Packets

This post covers the technical details of packet routing in Linux. Linux has
mechanisms in place to route packets using basic, "destination" based routing,
and advanced or policy-based routing. Part of the motivation for this deepdive
was the observation and subsequently exploited vulnerability by my buddies,
[William Tolley](https://williamtolley.com/), Beau Kujath, and [Jedidiah R
Crandall](https://jedcrandall.github.io/). He found that when a VPN is running
on Android, an attacker can spoof packets to the tun interface that match an
existing connection and that the Android device, more specifically, the process
with the connection, will respond. This went on to become known as the blind
in/on-path attack, this one being the socalled client-side attack.

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

The client-side attack works as follows. Assume that a target, `T`, is
connected to a VPN server, `V`, and has an ESTABLISHED TCP connection to a
website, `W`. `T` sends data to `W` by issuing `write`s (`send` or `sendmsg`)
to a socket, `_s_`. In Android the socket writes an `fwmark` from the socket to
the `skb` to be sent. As the `skb` travels down the network stack from `send`
to `ip_send` (or whatever its called), the kernel uses the `fwmark` to set the
`skb->dev` of the outgoing packet so that it can be written to the `tun` device
that represents the link-layer connection between `T` and `V`.  The VPN client
process on `T` intercepts this packet, encrypts the packet from layer 3 (IP)
and above, encasulates this packet by appending out layer 3 and 4 headers to
the packet, and sending it down to the link-layer driver for the wireless or
mobile model (`wlan0` or `rmnet1` in my case) to be transmitted to the next
hop, an eventually to `V`. 

The attacker can determine whether such a `T-W` connection exists in the
following way.  First, the attacker spoofs a packet `p` from `W` to the `T`. The
packet's structure is as follows. The link-layer header has a destination MAC
address that matches `wlan0`'s MAC address. The network layer header has a
source IP address equal to `W`'s public IP and a destination IP equal to
`tun0`'s private IP address. The transport layer header has a source port equal
to `W`'s listening port, and a destination port equal to the socket's port on
`W`. Additionally, the TCP seq and ack numbers need to be "in-window". finally,
the TCP flag should be set to `RST`. When this happens, the `T` will respond
with a challenge-ACK. The challenge ACK will.

This is bad for a number of reasons that are covered in William's USENIX Security 
paper. For this post, we are concerend with understanding where the break in 
process isolation occurs. Clearly the source address validation is a problem
because the packet is received on the WiFi interface but addressed to
the tun interface and a response is sent, but it would be good to understand better how
the fwmarks, routing tables, network names spaces, and associated interface
behavior along the input, forward, and output paths for incoming and outgoing
packets. Ultimately, what I hope to gain from this exercise are: 1) more practice
writing, because I need it; 2) a deeper understanding of Linux networking because 
when I first started doing security research I read books on Linux networking
internals and device driver development (the O'Reilly ones) because I thought
(and still think) low-level stuff is cool, and, 3) some insights about how to
break (and fix) it - I was always better at breaking things as a kid and I
don't see that changing any time soon.

# Initialization

For information on how the kernel initializations the network
stack, read my post about [Linux Network Initialization](https://bmixonba.github.io/2025-05-25-Linux-Networking-Initialization/).

# Networking Data Structure

When a packet reaches the network card the bytes in the cards DMA are
interepted using the `struct sk_buff` data structure defined in [`include/linux/skbuff.h`](https://github.com/torvalds/linux/blob/master/include/linux/skbuff.h#L883).

## Packet Representation 
```c
struct sk_buff {
	union {
		struct {
.
			union {
				struct net_device	*dev;
				/* Some protocols might use this space to store information,
				 * while device pointer would be NULL.
				 * UDP receive path is one user.
				 */
				unsigned long		dev_scratch;
			};
		};
.
        }
.
	struct sock		*sk;
.
 
.
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	unsigned long		 _nfct;
#endif
.
	__u8			__pkt_type_offset[0];
	/* public: */
	__u8			pkt_type:3; /* see PKT_TYPE_MAX */
.
.
	int			skb_iif;
.
#ifdef CONFIG_NETWORK_SECMARK
	__u32		secmark;
#endif

	union {
		__u32		mark;
		__u32		reserved_tailroom;
	};
.
}
```
Figure 1. Template for the `skb` operated on by various network functions.

This is a big datastructure, so I'm only including the members most 
relevant for the routing discussion. The semantics of the members are as follows:

 * @sk: Socket we are owned by
 * @dev: Device we arrived on/are leaving by
 * @dev_scratch: (aka @dev) alternate use of @dev when @dev would be %NULL
 * @pkt_type: Packet class
 * @_nfct: Associated connection, if any (with nfctinfo bits)
 * @skb_iif: ifindex of device we arrived on
 * @secmark: security marking
 * @mark: Generic packet mark

## Netwwork Device Data Structure

Another key data structure in networking is the `struct net_device`. It represents
network devices (DUH!) and has following definition:

```c
struct net_device {
.
	struct netdev_queue	*_tx;
.
#ifdef CONFIG_NETFILTER_EGRESS
	struct nf_hook_entries __rcu *nf_hooks_egress;
#endif
.
int			ifindex;
.
	struct netdev_rx_queue	*_rx;
	rx_handler_func_t __rcu	*rx_handler;
	void __rcu		*rx_handler_data;
	possible_net_t			nd_net;
.
	char			name[IFNAMSIZ];
.
#ifdef CONFIG_NETFILTER_INGRESS
	struct nf_hook_entries __rcu *nf_hooks_ingress;
#endif
.
```
Figure 2. Definition of a `struct net_device`. Located at [`include/linux/netdevice.h`](https://github.com/torvalds/linux/blob/master/include/linux/netdevice.h#L2080).

 * @_tx:			Array of TX queues
 * @nf_hooks_egress:	netfilter hooks executed for egress packets
 * @nf_hooks_egress:	netfilter hooks executed for egress packets
 * @_rx:			Array of RX queues
 * @rx_handler:		handler for received packets
 * @rx_handler_data: 	XXX: need comments on this one
 * @nd_net:		Network namespace this network device is inside
 * @name:	This is the first field of the "visible" part of this structure
 *		(i.e. as seen by users in the "Space.c" file).  It is the name
 *		of the interface.
 * @nf_hooks_ingress:	netfilter hooks executed for ingress packets

## Network Namespaces and Network Data Structures

The network namespace `nd_net` is defined as 
```c
typedef struct {
#ifdef CONFIG_NET_NS
	struct net __rcu *net;
#endif
} possible_net_t;
```
Figure 3. Definition of network namespace. Located at [`include/net/net_namespace.h`](https://github.com/torvalds/linux/blob/master/include/net/net_namespace.h#L397).

The `struct net` field in each `net_device is, I think, just a reference to the
`init_net` network namespace defined in
[`net/core/net_namespace.c`](https://github.com/torvalds/linux/blob/015a99fa76650e7d6efa3e36f20c0f5b346fe9ce/net/core/net_namespace.c#L48). Each network namespace contains a reference to the `user_namespace`, `user_ns`, for each "user" (process). This is used the enforce access control, such as checks to `CAP_SYS_ADMIN`. It also contains the routing rules (`rules_ops`), and IPv4 (and v6) related info in the `ipv4` struct, Netfilter, and conntrack related structures.

```c
struct net {
.
	u32			ifindex; /* Index of the device associated with the network */
.
	struct user_namespace   *user_ns;	/* Owning user namespace */
.
	/* core fib_rules */
	struct list_head	rules_ops;

	struct netns_core	core;
	struct netns_nexthop	nexthop;
	struct netns_ipv4	ipv4;
.
#ifdef CONFIG_NETFILTER
	struct netns_nf		nf;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct netns_ct		ct;
#endif
```
Figure 4. Definition of `struct net`. Located at [`include/net/net_namespace.h`](https://github.com/torvalds/linux/blob/master/include/net/net_namespace.h#L61).

The

```c
struct netns_nf {
.
	struct nf_hook_entries __rcu *hooks_ipv4[NF_INET_NUMHOOKS];
	struct nf_hook_entries __rcu *hooks_ipv6[NF_INET_NUMHOOKS];
.
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV4)
	unsigned int defrag_ipv4_users;
#endif
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
	unsigned int defrag_ipv6_users;
#endif
}
```
Figure 5. Netfilter network namespace stores a set of hooks that are added to the namespace
for processing packets. 

The `Netfitler` hooks, `hooks_ipv4` and `hooks_ipv6` are called when Netfilter
is envoked. The details of this are covered later when we walk through the
first time Netfilter is called. The `ipv4` variable also has a `rules_ops`
field which is used by the routing code for policy-routing decisions. The
`nexthop` field is used for routing. 

```c
struct netns_ipv4 {
.
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rules_ops	*rules_ops;
	struct fib_table __rcu	*fib_main;
	struct fib_table __rcu	*fib_default;
#endif
.
```
Figure 6. Routing related data structures for IPv4 routing. Located at [`include/net/netns/ipv4.h`](https://github.com/torvalds/linux/blob/master/include/net/netns/ipv4.h#L50).

When Linux is configured to support multiple routing tables, the `netns_ipv4`
struct includes at least `fib_main` representing the `MAIN` fib table and
`fib_default` representing the default routes to use (I Think). Linux supports
up to 250-ish tables. The `DEFAULT` and `MAIN` tables have reserved indecies.
I'm currently not sure where the user-defined tables are stored.

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
Figure 7. Identifiers for routing tables. Located at [`include/uapi/linux/rtnetlink.h`](https://elixir.bootlin.com/linux/v6.14.4/source/include/uapi/linux/rtnetlink.h#L355)

### Routing Tables

Each table has one or more rules associated with it. A user can define up to
252 unique routing tables. The tables can be defined either using a string or a
number, but those are mapped to an integer.  There are also four predefined
routing tables, 

1. `CAMPAT`: This routing table is for background compatibility with older
             versions of Linux (XXX - I am making this up and need to verify
             that it is true)
2. `DEFAULT`: The `DEFAULT` routing table is used when no other tables are applicable for a packet.
3. `MAIN`: The `MAIN` routing tables is used for XXX.
4. `LOCAL`: The `LOCAL` routing table is used for packets generated and received by the local processes.

When multiple tables are supported, a user or program can define them
using either the `iproute2` tool or talking with `netlink` directly.
These are represented in the kernel by the `fib_table` data structure.

## Forward Information Base (FIB) Data Structure

The Forwarwd Information base (FIB) is the name of the routing data structure
used to represent routes. 

```c
struct fib_table {
	struct hlist_node	tb_hlist;
	u32			tb_id;
	int			tb_num_default;
	struct rcu_head		rcu;
	unsigned long 		*tb_data;
	unsigned long		__data[];
.
};
```
Figure 8. Defintion of a FIB table in Linux. Located at [`include/net/ip_fib.h`](https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L257).

Routing rules are represented by the `fib_rules_ops` data structure. This is a
structure that organizes a number of callback functions that are called for
various routing operations, such as matching rules and configuring routing
rules. 

```c
struct fib_rules_ops {
.
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct fib_rule_hdr *,
					     struct nlattr **,
					     struct netlink_ext_ack *);
.
}
```
Figure 9. Data structure representing actions to be made during routing
decisions. Located at
[`include/net/fib_rules.h`](https://github.com/torvalds/linux/blob/master/include/net/fib_rules.h#L64).

The `fib_rule` represents a routing rule. 

```c

struct fib_rule {
	struct list_head	list;
	int			iifindex;
	int			oifindex;
	u32			mark;
	u32			mark_mask;
.
	u32			target;
.
}
```
Figure 10. Defintion of a FIB routing rule. Located in [`include/net/fib_rules.h`](https://github.com/torvalds/linux/blob/master/include/net/fib_rules.h#L20).

Take the following routing rule as an example:

```bash
11000:	from all iif lo oif wlan0 uidrange 0-0 lookup wlan0 
```
Figure 11. Example routing rule.

This rule states that any incoming packets (`from all`) that are locally
generated ('iff lo`) and destined for the wifi interface (`oif wlan0`) with the
root uid (`uidrange 0-0`) should lookup the routing rules in the `wlan0`
network (`lookup wlan0`).


In another post, I will cover `netlink` and/or the `iproute2` tool that are
used to configure the fib rules. For now, I'm just going to make some educated
guesses about what the rules look like based on the output of the `ip rule` and
`ip route` commands.

## Routing Rules for this Post

For this post, I will assume the following routing rules:

```bash
lynx:/ $ ip rule show table 1046
11000:	from all iif lo oif wlan0 uidrange 0-0 lookup 1046 
15040:	from all fwmark 0x10066/0x1ffff iif lo uidrange 10179-10179 lookup 1046 
16000:	from all fwmark 0x10066/0x1ffff iif lo lookup 1046 
17000:	from all iif lo oif wlan0 lookup 1046 
22040:	from all fwmark 0x66/0x1ffff iif lo uidrange 10179-10179 lookup 1046 
23000:	from all fwmark 0x66/0x1ffff iif lo lookup 1046 
28000:	from all fwmark 0x68/0xffff lookup 1046 
29040:	from all fwmark 0x0/0xffff iif lo uidrange 10179-10179 lookup 1046 
31000:	from all fwmark 0x0/0xffff iif lo lookup 1046 

lynx:/ $ ip route show table 1046                                                                                                            
default via 10.0.0.1 dev wlan0 proto static 
10.0.0.0/24 dev wlan0 proto static scope link 
```
Figure 12. `wlan0` routing table is 1046 and accompanying routes.


```bash
lynx:/ $ ip rule | grep tun                                                                                                       
12000:	from all iif tun1 lookup 97 
17000:	from all iif lo oif tun1 uidrange 0-10307 lookup 1050 
17000:	from all iif lo oif tun1 uidrange 10309-20307 lookup 1050 
17000:	from all iif lo oif tun1 uidrange 20309-99999 lookup 1050 

lynx:/ $ ip rule | grep 1050
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 0-10307 lookup 1050 
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 10309-20307 lookup 1050 
13000:	from all fwmark 0x0/0x20000 iif lo uidrange 20309-99999 lookup 1050 
13000:	from all fwmark 0xc0068/0xcffff lookup 1050 
16000:	from all fwmark 0x10068/0x1ffff iif lo uidrange 0-10307 lookup 1050 
16000:	from all fwmark 0x10068/0x1ffff iif lo uidrange 10309-20307 lookup 1050 
16000:	from all fwmark 0x10068/0x1ffff iif lo uidrange 20309-99999 lookup 1050 
16000:	from all fwmark 0x10068/0x1ffff iif lo uidrange 0-0 lookup 1050 
17000:	from all iif lo oif tun1 uidrange 0-10307 lookup 1050 
17000:	from all iif lo oif tun1 uidrange 10309-20307 lookup 1050 
17000:	from all iif lo oif tun1 uidrange 20309-99999 lookup 1050 
```
Figure 13. Policy-routing for `tun1` and its associated table `1050`.

```bash
lynx:/ $ ip route show table 1050
0.0.0.0/2 dev tun1 proto static scope link 
.
.
128.0.0.0/1 dev tun1 proto static scope link
```
Figure 14. Routes associated with `tun1` routing table.

These rules were taken from my rooted Pixel7a Android device with a VPN
installed (for more info on how to root a Pixel7a, check out my other post
[Rooting Android](https://bmixonba.github.io/2025-05-26-Rooting-Android/)).

Whenever a packet enters or leaves the system, these rules are consulted to
make a routing decision. Notice that many of them use the `fwmark/fwmask` for
decisions. From what I understand according to Lorenzo Colitti's
[presentatoin](https://netdevconf.info/1.1/proceedings/slides/colitti-kline-linux-networking-android-devices.pdf)),
Android uses these constructs to properly route packets between interfaces on
mobile devices. But how do these marks actually get placed on the `skb` if
there are not explicitly part of the packet represented by the `skb`? That's where
Netfilter comes into play.

## `fwmark`s for this Post

Android adds `fwmark/fwmask` using `iptables`, Netfilter, and kernel supported
packet marking for packets written to a socket via the `SO_MARK` socket option,
[man7-socket](https://www.man7.org/linux//man-pages/man7/socket.7.html). The
following `fwmark/fwmask` rules will be assumed for this post and were dumped
from my Pixel while I was analyzing VPNs.

```bash
lynx:/ # iptables -t mangle -S -v
-P PREROUTING ACCEPT -c 2584 728459
-P INPUT ACCEPT -c 2583 728114
-P FORWARD ACCEPT -c 0 0
-P OUTPUT ACCEPT -c 4168 369913
-P POSTROUTING ACCEPT -c 4171 370108
-N bw_mangle_POSTROUTING
-N connmark_mangle_INPUT
-N connmark_mangle_OUTPUT
-N idletimer_mangle_POSTROUTING
-N oem_mangle_post
-N routectrl_mangle_INPUT
-N tetherctrl_mangle_FORWARD
-N wakeupctrl_mangle_INPUT
-A INPUT -c 2583 728114 -j connmark_mangle_INPUT
-A INPUT -c 2583 728114 -j wakeupctrl_mangle_INPUT
-A INPUT -c 2583 728114 -j routectrl_mangle_INPUT
-A FORWARD -c 0 0 -j tetherctrl_mangle_FORWARD
-A OUTPUT -c 4168 369913 -j connmark_mangle_OUTPUT
-A POSTROUTING -c 4171 370108 -j oem_mangle_post
-A POSTROUTING -c 4171 370108 -j bw_mangle_POSTROUTING
-A POSTROUTING -c 4171 370108 -j idletimer_mangle_POSTROUTING
-A bw_mangle_POSTROUTING -o ipsec+ -c 0 0 -j RETURN
-A bw_mangle_POSTROUTING -m policy --dir out --pol ipsec -c 0 0 -j RETURN
-A bw_mangle_POSTROUTING -c 4171 370108 -j MARK --set-xmark 0x0/0x100000
-A bw_mangle_POSTROUTING -m bpf --object-pinned /sys/fs/bpf/netd_shared/prog_netd_skfilter_egress_xtbpf -c 4171 370108
-A connmark_mangle_INPUT -m connmark --mark 0x0/0xfffff -c 262 19122 -j CONNMARK --save-mark --nfmask 0xfffff --ctmask 0xfffff
-A connmark_mangle_OUTPUT -m connmark --mark 0x0/0xfffff -c 1466 83327 -j CONNMARK --save-mark --nfmask 0xfffff --ctmask 0xfffff
-A idletimer_mangle_POSTROUTING -o rmnet1 -c 0 0 -j IDLETIMER --timeout 10 --label 100 --send_nl_msg
-A idletimer_mangle_POSTROUTING -o wlan0 -c 3495 291406 -j IDLETIMER --timeout 15 --label 102 --send_nl_msg
-A idletimer_mangle_POSTROUTING -o rmnet2 -c 25 2535 -j IDLETIMER --timeout 10 --label 103 --send_nl_msg
-A routectrl_mangle_INPUT -i rmnet1 -c 0 0 -j MARK --set-xmark 0xf0064/0x7fefffff
-A routectrl_mangle_INPUT -i wlan0 -c 1991 324525 -j MARK --set-xmark 0x30066/0x7fefffff
-A routectrl_mangle_INPUT -i rmnet2 -c 18 6034 -j MARK --set-xmark 0x30067/0x7fefffff
-A routectrl_mangle_INPUT -i tun1 -c 102 37610 -j MARK --set-xmark 0x30068/0x7fefffff
-A tetherctrl_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -c 0 0 -j TCPMSS --clamp-mss-to-pmtu
-A wakeupctrl_mangle_INPUT -i rmnet1 -m mark --mark 0x80000000/0x80000000 -m limit --limit 10/sec -c 0 0 -j NFLOG --nflog-prefix "432902426637:rmnet1" --nflog-group 3 --nflog-threshold 8
-A wakeupctrl_mangle_INPUT -i wlan0 -m mark --mark 0x80000000/0x80000000 -m limit --limit 10/sec -c 295 15316 -j NFLOG --nflog-prefix "441492361229:wlan0" --nflog-group 3 --nflog-threshold 8
-A wakeupctrl_mangle_INPUT -i rmnet2 -m mark --mark 0x80000000/0x80000000 -m limit --limit 10/sec -c 0 0 -j NFLOG --nflog-prefix "445787328525:rmnet2" --nflog-group 3 --nflog-threshold 8
-A wakeupctrl_mangle_INPUT -i tun1 -m mark --mark 0x80000000/0x80000000 -m limit --limit 10/sec -c 0 0 -j NFLOG --nflog-prefix "450082295821:tun1" --nflog-group 3 --nflog-threshold 8
```
Figure 15. Netfilter rules to mark packets.

The `mangle` table is the only table with meaingful rules, so I didn't include
the others. The `mangle` table looks like:

```bash
lynx:/ # iptables -t mangle -L -vn                                                                                                           
Chain PREROUTING (policy ACCEPT 2577 packets, 728K bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain INPUT (policy ACCEPT 2576 packets, 728K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 2576  728K connmark_mangle_INPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
 2576  728K wakeupctrl_mangle_INPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
 2576  728K routectrl_mangle_INPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 tetherctrl_mangle_FORWARD  all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain OUTPUT (policy ACCEPT 4158 packets, 369K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4158  369K connmark_mangle_OUTPUT  all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain POSTROUTING (policy ACCEPT 4161 packets, 369K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 4161  369K oem_mangle_post  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
 4161  369K bw_mangle_POSTROUTING  all  --  *      *       0.0.0.0/0            0.0.0.0/0           
 4161  369K idletimer_mangle_POSTROUTING  all  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain bw_mangle_POSTROUTING (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 RETURN     all  --  *      ipsec+  0.0.0.0/0            0.0.0.0/0           
    0     0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            policy match dir out pol ipsec
 4161  369K MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK and 0xffefffff
 4161  369K            all  --  *      *       0.0.0.0/0            0.0.0.0/0           match bpf pinned /sys/fs/bpf/netd_shared/prog_netd_skfilter_egress_xtbpf

Chain connmark_mangle_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
  262 19122 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            connmark match  0x0/0xfffff CONNMARK save mask 0xfffff

Chain connmark_mangle_OUTPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
 1466 83327 CONNMARK   all  --  *      *       0.0.0.0/0            0.0.0.0/0            connmark match  0x0/0xfffff CONNMARK save mask 0xfffff

Chain idletimer_mangle_POSTROUTING (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 IDLETIMER  all  --  *      rmnet1  0.0.0.0/0            0.0.0.0/0            timeout:10 label:100 send_nl_msg
 3490  291K IDLETIMER  all  --  *      wlan0   0.0.0.0/0            0.0.0.0/0            timeout:15 label:102 send_nl_msg
   25  2535 IDLETIMER  all  --  *      rmnet2  0.0.0.0/0            0.0.0.0/0            timeout:10 label:103 send_nl_msg

Chain oem_mangle_post (1 references)
 pkts bytes target     prot opt in     out     source               destination         

Chain routectrl_mangle_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 MARK       all  --  rmnet1 *       0.0.0.0/0            0.0.0.0/0            MARK xset 0xf0064/0x7fefffff
 1984  324K MARK       all  --  wlan0  *       0.0.0.0/0            0.0.0.0/0            MARK xset 0x30066/0x7fefffff
   18  6034 MARK       all  --  rmnet2 *       0.0.0.0/0            0.0.0.0/0            MARK xset 0x30067/0x7fefffff
  102 37610 MARK       all  --  tun1   *       0.0.0.0/0            0.0.0.0/0            MARK xset 0x30068/0x7fefffff

Chain tetherctrl_mangle_FORWARD (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 TCPMSS     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp flags:0x02/0x02 TCPMSS clamp to PMTU

Chain wakeupctrl_mangle_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 NFLOG      all  --  rmnet1 *       0.0.0.0/0            0.0.0.0/0            mark match 0x80000000/0x80000000 limit: avg 10/sec burst 5 nflog-prefix "432902426637:rmnet1" nflog-group 3 nflog-threshold 8
  292 15184 NFLOG      all  --  wlan0  *       0.0.0.0/0            0.0.0.0/0            mark match 0x80000000/0x80000000 limit: avg 10/sec burst 5 nflog-prefix "441492361229:wlan0" nflog-group 3 nflog-threshold 8
    0     0 NFLOG      all  --  rmnet2 *       0.0.0.0/0            0.0.0.0/0            mark match 0x80000000/0x80000000 limit: avg 10/sec burst 5 nflog-prefix "445787328525:rmnet2" nflog-group 3 nflog-threshold 8
    0     0 NFLOG      all  --  tun1   *       0.0.0.0/0            0.0.0.0/0            mark match 0x80000000/0x80000000 limit: avg 10/sec burst 5 nflog-prefix "450082295821:tun1" nflog-group 3 nflog-threshold 8
```
Figure 16. Netfilter tables.

The routing rules, Netfilter, and socket-supported `fwmark` marks allow Android
to route packets between interfaces in the face of the user constantly
switching networks, IP addresses, and multiple interfaces of different types
(i.e., tuntap, wireguard, mobile data, and Wifi). Notice that the default
policies are fail-open (ACCEPT), so that weird packets will be routed, even if
they are in an invalid state or, as William, Beau, and Jed discovered, fail
source address validation.

The important rules that add `fwmarks` to packets are configured in the
`routectrl_mangle` chain. These hooks are added to the mangle table's `INPUT`
chain. The first set of hooks related to packet reception are `NF_INET_PRE_ROUTING`,
`NF_INET_LOCAL_IN` , and `NF_INET_FORWARD`.

```c
        [NFT_TABLE_MANGLE] = {
                .name   = "mangle",
                .type   = NFT_TABLE_MANGLE,
                .chains = {
                        {
                                .name   = "PREROUTING",
                                .type   = "filter",
                                .prio   = -150, /* NF_IP_PRI_MANGLE */
                                .hook   = NF_INET_PRE_ROUTING,
                        },
                        {
                                .name   = "INPUT",
                                .type   = "filter",
                                .prio   = -150, /* NF_IP_PRI_MANGLE */
                                .hook   = NF_INET_LOCAL_IN,
                        },
                        {
                                .name   = "FORWARD",
                                .type   = "filter",
                                .prio   = -150, /* NF_IP_PRI_MANGLE */
                                .hook   = NF_INET_FORWARD,
                        },
```
Figure 17. `iptables` code for adding hooks on the various recieve paths of the `mangle` table. Located at [`iptables/iptables/nft.c`](https://git.netfilter.org/iptables).

## Data Structure Representation in this Post

Throughout the post, I will represent kernel data structures using something
like a python or json dictionary. As `skb` moves through the network stack, I
will update it accordingly. 

```bash
# Network Devices
struct net_device devWlan0 = {name:"wlan0", ifid:2, nd_net:netWlan0, _rx:[skbAttacker], _tx:[]}
struct net_device devRmnet1 = {name:"rmnet1", ifid:3, nd_net:netRmnet0, _rx:[], _tx:[]}
struct net_device devTun0 = {name:"tun0", ifid:4, nd_net:netTun0, _rx:[], _tx:[]}

# Attacker packet
struct sk_buff skbAtk = {dev:None, sk:None,_nfct:0, pkt_type=<UNKNOWN>, skb_iif=<UNKNOWN MAYBE 2>, secmark=0, mark=0}

# Wlan0 Network Namespace, FIB table and rules
struct net netWlan0 = {ipv4:netns_ipv4_wlan0}
struct netns_ipv4_wlan0 = {rules_ops : rules_ops_wlan0, fib_main: fib_main_wlan0, fib_default: fib_default_wlan0}
struct fib_table fib_default_wlan0 = [
  {via:10.0.0.1, dev: wlan0, proto: static}
]
struct fib_table fib_main_wlan0 = [
  {via: 10.0.0.0/24, dev: wlan0, proto: static, scope:link}
.
]
struct fib_rules_ops rules_ops_wlan0 = {
    {from : all, iif:lo,oif:wlan0, uidrange : 0-0,  action: lookup, table:fib_main_wlan0}
.
}

# tun1 Network Namespace, FIB table and rules
struct net netTun0 = {ipv4:netns_ipv4_tun1}
struct netns_ipv4_tun1 = {rules_ops : rules_ops_tun1, fib_main: fib_main_tun1, fib_default: fib_default_tun1}
struct fib_tables fib_main_tun1 = [
    {via:0.0.0.0/2, dev:tun1, proto: static, scope:link}
.
.
    {via: 128.0.0.0/1, dev: tun1,  proto: static, scope:link}
]
struct fib_tables fib_default_tun1 = []
struct fib_rules_ops rules_ops_tun1 = {
    {from:all,fwmark:0x0, fwmask:0x20000, iif:lo, uidrange:0-10307, action : lookup fib_main_tun1}
    {from:all,fwmark:0xc0068, fwmask:0xcffff, lookup 1050}
    {from:all,fwmark:0x10068, fwmask:0x1ffff, iif:lo, uidrange:0-10307 action :lookup fib_main_tun1}
.
    {from:all, fwmark:0x10068 fwmask:0x1ffff, iif:lo, uidrange:0-0, action: lookup fib_main_tun1}
.
    {from:all, iif:lo, oif:tun1, uidrange:0-10307, action: lookup fib_main_tun1}
}
```
Figure 18. Routing data structure used for this post.

# Packet Reception

After `A` (me) spoofs the packet, `skbAtk`, to `T` (you), the digital
represetion is transformed into an analogue (electircal or luminal) signal that
travels at some constant, `k` multiplied by the `c` (the speed of light),
`k*c`. It eventually reaches `T`'s device's network interface card, which acts
as an `ADC` or analogue-to-digital-converter where it is converted to a digital
signal and stored in the network card's memory or the DMA of the CPU if a SoC
(I think). Depending on the kernel, he card either raises an interupt with the
CPU of your device which induces the Kernel to execute some interrupt request
handler to process the packet (I think?) or the kernel periodically invokes a
NAPI function to process packets in chunks. I will cover NAPI a bit later, but
for now all you need to know is that on older versions of Linux, the former
is used, while NAPI is used, to the best of my knowledge, on newer versions
of Linux.

This is the Link layer (Layer 2) and is the interface between analogue to
digital signals and the network (IP) layer. The link layer then processes the
packet and passes it up to the network layer (Layer 3) which further processes
and routes the packet. In the routing step, the network layer inspects the
destination ip address of `skbA` and either passes it to the forwarding path or
up the network stack to the transport layer (Layer 4). In the former case, the
network layer will either write `skbA` to a different interface on the same
device, e.g., wlan0 to tun1 or send it to a "neighbor" device, such as my home
wifi access point or mobile carrier network, or pass it further up to the
transport layer, consuming it.

## Link Layer

Regadless of which interface is called, each has a set of functions
that it registers with the kernel, informing  the kernel that
when a particular even happens, it should call the registered function.

### WiFi

As described in my post, [Linux Networking
Initialization](https://bmixonba.github.io/2025-05-25-Linux-Networking-Initialization/),
each interface is represented by a `struct net_device` and has a set of
associated `poll` function that it registers when using NAPI. For the Qualcomm
device, `wlan0`, the `emac_napi_poll` is the poll function called to handle received packets.

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
Figure 19. Packet reception code `emac_napi_rtx` in [`drivers/net/qualcomm/emac/emac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac.c#L96).

This is just a wrapper for `emac_mac_rx_process`, which does the actual packet
processing and calls, e.g., the `af_inet` (TCP/IP) stack.  Before this happens
internal book keeping, such as setting the Layer 3 protocol is set and sanity
checks are performed. For the Qualcomm driver, the generic receiption
offloading (GRO) framework is used instead of calling the `ip_rcv` routine
directly every time an packet is received.

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
Figure 20. Code to pull a packet from the Qualcomm `rx` queue and call, e.g.,
`af_inet`, in
[`drivers/net/qualcomm/emac-emac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac-mac.c#L1087).

The driver sets up `skbAtk`, such as setting the `devWlan0` field of `skbAtk` to
the device on which the `skbAtk` was received. It then
calls `napi_gro_receive`. GRO is resonsible for aggregating packets for the
same stream before delivering them to the network stack. 

```bash
struct sk_buff skbAtk = {dev:devWlan0, sk:None,_nfct:0, pkt_type=<UNKNOWN>, skb_iif=<UNKNOWN MAYBE 2>, secmark=0, mark=0}
```
Figure 21. `skbAtk` after the call to `emac_mac_rx_process

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
Figure 22. Qualcomm card delivering `skb` to upper layers _via_ NAPI. In [`drivers/net/qualcomm/emac/emac-mac.c`](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/qualcomm/emac/emac-mac.c#L1071).

Like NAPI, GRO (Generic Receiver Offload) is a technique the Linux kernel uses
to aggregate groups of packets for the same stream and pass them up the network
stack at once instead of processing every single packet as it is received. For
more information on GRO, check out the article by
[DPDK](https://doc.dpdk.org/guides/prog_guide/generic_receive_offload_lib.html).

The `napi_gro_receive` function is a wrapper that does bookkeeping before calling 
and includes calls to trace the flow of `skbAtk` through the system
before calling `dev_gro_receive`.

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
Figure 23. GRO receive function calls `dev_gro_receive` to pass the `skb` up the network
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
Figure 24. GRO calling the `af_inet` packet reception code `inet_gro_receive` for IPv4 or `ipv6_gro_receive` for IPv6. 
More details at [`net/core/gro.c#L460`](https://github.com/torvalds/linux/blob/master/net/core/gro.c#L460).

The `gro_*` functions for IP and TCP/UDP are used to aggregate fragmented (and
segmented?) packets, but do not make any routing decisions.

Once the packet stream has been collated, `gro_receive_skb` calls `gro_receive_finish`.

```c
static gro_result_t gro_skb_finish(struct gro_node *gro, struct sk_buff *skb,
				   gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
		gro_normal_one(gro, skb, 1);
		break;
.
.
}
```
Figure 25. `gro_skb_finish` is called once GRO has aggregated a stream of packets. Details at [`net/core/gro.c`](https://github.com/torvalds/linux/blob/master/net/core/gro.c#L596).

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
Figure 26. `gro_normal_one` is used to pass the aggregated packets up the stack. Details at [`include/net/gro.h`](https://github.com/torvalds/linux/blob/master/include/net/gro.h#L540).

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
Figure 27. Device receive function interface. This function recieves a list of `skb`s from GRO
and passes them up the network stack. Located in [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L6091)


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
}
```
Figure 28. More indirection to get to Network stack. Mostly book keeping for
memory and to process the list of GRO packets. Located in
[`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L6005).

The `__netif_receive_skb_list_core` is the "core" function for handling lists of packets
sent up the network stack from GRO. This function organizes all of the packets of a particular
type into a single, homogeneous sublist and then passes it to 
`__netif_receive_skb_list_ptype` to call the network layer receive handler for that specific `packet_type`.

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
Figure 29. Located in [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L5939)

Finally, the `__netif_receive_skb_list_ptype` calls `ip_rcv` (or `ip_list_rcv`)
for `skbAtk`.  Up to this point, only a few fields in `skbAtk` have change. The
`dev` and `protocol` fields have been changed. A few others have also been
changed, but from what I can tell, they do not affect routing. Notably, neither
the `sk` nor `mark` fields have been changed. As we will see, this happens
in the network layer code.

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
Figure 30. Located at [`net/core/dev.c`](https://github.com/torvalds/linux/blob/master/net/core/dev.c#L5919) 

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

VPNs are typically configured with a `tun` device and are defined in
[`drivers/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c).
The `tun` is a character device (and as always, represented as a file). This is
backed by the `tun_struct` structure

```c

struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;

```
Figure 31. `tun_struct` representing a tun device.



```c
static int __init tun_init(void)
{
	int ret = 0;

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);

	ret = rtnl_link_register(&tun_link_ops);
.
```
Figure 32. tun registration routine.


```c
/* Ops structure to mimic raw sockets with tun */
static const struct proto_ops tun_socket_ops = {
	.peek_len = tun_peek_len,
	.sendmsg = tun_sendmsg,
	.recvmsg = tun_recvmsg,
};

```
Figure 33. `tun_socket_ops` callbacks used to receive packets. Defined in [`driver/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c#L955).

```c
static int tun_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		       int flags)
{
```
Figure 34. Main receive function for tunnel device. Defined in [`driver/net/tun.c`](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c#L2538)

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
Figure 35. The receive routine registered with the kernel. Details at [`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#558)

The `ip_rcv_core` function is used to get the `skb` ready for processing
further up the network stack. This includes removing padding that may have been
added by the receiving network card, making sure the header length and checksum
are correct, and setting the transport layer header pointer,
`skb->transport_header`.

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
Figure 36. `ip_rcv_core` is mainly used for book keeping and sanity checking the packet. Details at [`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L454)

After `skbAtk` is confirmed to be legit and the appropriate book keeping has
been done (e.g., `transport_header` pointer for `skbAtk` has been updated),
`ip_rcv` calls `ip_rcv_finish` as a function to be called after the rules in
`Netfilter`'s `PREROUTING` hook have been executed. From what I can tell,
unlike the classic `Netfilter` diagram that shows the `PREROUTING` chains being
called in the Link Layer (Bridge layer in the diagram), it is actually called for the first
time just before the IP layer makes any routing decisions. 

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
Figure 37. Located at [`include/linux/netfilter.h`](https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h#L307).

`NF_HOOK` wraps for the underlying `nf_hook` function that
handles the return codes for the Netfilter hooks and ultimately calls
`ip_rcv_finish` if the packet is allowed to `PASS`. For any other return code, 
the hook consumes the `skb`

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
1. Where and when is the device's network name space `dev` initialized?

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
Figure 38. Netfilter wrapper function to determine which hook to execute. Details at [`include/linux/netfilter.h`](https://github.com/torvalds/linux/blob/master/include/linux/netfilter.h#L223).

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
Figure 39. Routine to loop through Netfilter rules. Details at [`net/netfilter/core.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/core.c#L617).

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
Figure 40. The function called by the Netfilter hook code, `okfn` when the
packet is allowed the "PASS". Located at
[`net/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L433).

The `ip_rcv_finish` function is responsible for checking whether the "ingress
device is enslaved to an L3 master", otherwise, it calls the actual routing
code, `ip_rcv_finish_core`.

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
Figure 41. Located at [`net/ipv4/ip_input.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/ip_input.c#L317).

The `ip_rcv_finish_core` function calls into the routing code to set up the
route for `skbAtk`, either to be consumed by the higher layer protocol or
forwarded. In our case, `skbAtk` should take the forwarding path because
it was received by `wlan0`.

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
Figure 42. Located at [`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2526).

`ip_route_input_noref` stores the results of the route lookup in the `struct fib_result res` variable.
It then calls `ip_route_input_rcu` after acquiring an rcu read lock (`rcu_read_lock`). Functions
throughout the kernel have the string `_rcu` to indicate that the caller holds an rcv lock for during
the call. `ip_route_input_rcu` takes `skbAtk` the addresses, device `dev`, and a pointer the the
routing results `res` where the results are stored.

```c
// TODO, add in_route_input_rcu code

```
Figure 43. `ip_route_input_rcu`. Located at [`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2474).

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
Figure 44. `ip_route_input_slow` in [route.c](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2908)

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
Figure 45. `fig_lookup` for multiple tables [374](https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L374).


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
Figure 46. Located at [``](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L83).


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
Figure 47. in `fig_rules.c` Line [108](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L108)


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
Figure 48. Routine for policy-based routing decisions. Located at [`net/core/fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/core/fib_rules.c#L278).

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
Figure 49. Located at [`net/ipv4/fib_rules.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_rules.c#L110).

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
Figure 50. `fib_get_table` when Linux is configured to support multiple routing tables. Located at [``](https://github.com/torvalds/linux/blob/b1427432d3b656fac71b3f42824ff4aea3c9f93b/net/ipv4/fib_frontend.c#L111).



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
Figure 51. Source address validation for locally destined packets. Located at [`net/ipv4/fib_frontend.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c#L428.).


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
Figure 52. Located at [`fib_frontend.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c#L344).


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
Figure 53. Call to `ip_mkroute_input` with the `fib_result` passed. Located at[`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L2149).

TODO: 

1. Does android have multipath configured?

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
Figure X. Located at [`net/ipv4/route.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c#L1797).

`TODO`
1. Are classids defind in Android?

![Netfilter](https://bmixonba.github.io/assets/img/blog/Netfilter-packet-flow.png)
Netfilter calling points for different tables and default chains.
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
