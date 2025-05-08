# Android VPN Internals: Netfilter

In this post, I will cover how Android implements its VPN functionality at the kernel level.

# Background

## Host Model: Strong Host Model versus Weak Host Model

In computer networking, there are two ways of modeling how a device processes
incoming unicast (TCP|UDP)/IP packets, the so-called `strong host` and
`weak host` models. 

### Strong Host

In the strong-host model, when a host receives an incoming packet, the packet
is only processed if the packet's destination IP address matches the IP address
of the network interface card (NIC) on which it was received.  The strong host
model provides better security and mitigates ``client-side'' blind in/on-path
attacks, e.g., [Tolley et al.'s
attack](https://www.usenix.org/system/files/sec21-tolley.pdf). While preventing
such attacks, the strong host model may cause connectivity problems. Examples
of operating systems whose IP implementation supports the strong host model are
Windows Vista and Windows 2008 Server, and OpenBSD v>= 6.6. These operating
systems also implement source address `sysctl rp_filter=1` which is not the
same as the strong host model, but prevents many of VPN-specific attacks that
abuse packet routing.

### Weak Host

In the weak host model, the TCP/IP implementation will accept incoming unicast
packets destined for any NIC on the device as long as the packet's destination
IP matches one of the NIC IPs. Most modern operating systems default to the
weakhost model including Linux, Windows, FreeBSD, NetBSD, and DragonflyBSD[1].
The benefit of a weak-host model is increased connectivity though it comes
at the expense of security (typical... :{)

## Routing Policy

When a machine recieves packets, either destined for it or some other machine (i.e., it is a router),
the machine must decided where to route the packet. The strategies for routing packets are static routing,
dynamic routing, or policy-based routing.

### Static Routing

Static routing is the simplest and most computationally efficient routing
strategy. In static routing, the destination IP of a packet is often used to
determine where to route the packet.

### Dynamic Routing

### Policy-based Routing

Policy-based routing is the most computationlly expensive routing stategy because
the machine must now inspect potentially the entire header and payload to decide
to which host/NIC a packet should be routed.

### Multi-homed

Multi-homed refers to scenarios where a device has multiple NICs each connected to
the Internet. Mobile devices are examples of multi-homed devices because they have
multiple NICs (e.g, WiFi, mobile, SMS, etc.).

# Androids Strong Host Implementation 

Android implements the strong host model[2] (slide 10). Unforunately, because
the operating system, Linux, defaults to the weak host model and because mobile
devices are multi-homed, Android has to mimic strong host behavior. To do this,
Android uses a combination of firewall (Netfilter) and kernel supported
features to implement policy-based routing, some of which Android has
integrated into the upstream Linux kernel.

## Linux Modifications

## Netfilter Modifications



## Netfilter


# References

[1](https://en.wikipedia.org/wiki/Host_model)
[2](https://netdevconf.info/1.1/proceedings/slides/colitti-kline-linux-networking-android-devices.pdf)
