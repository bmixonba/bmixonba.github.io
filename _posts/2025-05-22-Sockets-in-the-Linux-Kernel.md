# Sockets in the Linux Kernel


## Sockets

The first thing you do when writing any network code is open a `socket`. A socket is a special type 
of file in Linux. Socket creation is handled the `socket` system call. The code for this
lives in [net/socket.c](https://github.com/torvalds/linux/blob/master/net/socket.c#L1621). When 
setting up a socket from user space, you generally specific the type of socket, e.g., `AF_INET`,
and the type, such as `SOCK_STREAM` for TCP or `SOCK_DGRAM` for UDP.


```c
/**
 *	__sock_create - creates a socket
 *	@net: net namespace
 *	@family: protocol family (AF_INET, ...)
 *	@type: communication type (SOCK_STREAM, ...)
 *	@protocol: protocol (0, ...)
 *	@res: new socket
 *	@kern: boolean for kernel space sockets
 *
 *	Creates a new socket and assigns it to @res, passing through LSM.
 *	Returns 0 or an error. On failure @res is set to %NULL. @kern must
 *	be set to true if the socket resides in kernel space.
 *	This function internally uses GFP_KERNEL.
 */

int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{

.

	err = pf->create(net, sock, protocol, kern); // Line 1541
.

```

The underlying semantics of the `family` and `type` are the same between the user-space function
call and the low-level call above. The underlying `create` function is configured by the
protocol family (PF), which, for this example is `AF_NET`. This is defined in a struct in `net/af_inet.c`,
specifically, `inet_create`.

```c
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{



	if (!kern) {
		err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
		if (err)
			goto out_sk_release;
	}

```
Figure. Socket creation in [`net/af_net.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L252)


I am currently not sure how the `create` set 
