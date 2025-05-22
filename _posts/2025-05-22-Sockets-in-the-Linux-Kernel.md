# Sockets in the Linux Kernel


## Sockets

The first thing you do when writing any network code is open a `socket`. A socket is a special type 
of file in Linux. Socket creation is handled the `socket` system call. The code for this
lives in [net/socket.c](https://github.com/torvalds/linux/blob/master/net/socket.c#L1621). When 
setting up a socket from user space, you generally specific the type of socket, e.g., `AF_INET`,
and the type, such as `SOCK_STREAM` for TCP or `SOCK_DGRAM` for UDP.

```c

void server() {
   sockfd = socket(AF_INET, SOCK_STREAM);
.
.
.
}
```


## `create` Socket Systemcall

The code below is the `socket` system call code that ultimately calls into the `af_net` 
networking code.

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

After the socket is created, we can either `listen` and `accept` if we are developing a server or `connect if we 
are developing a client program.

### Listen

```c

void server() {
.
    int backlog = 128;
    int ret = listen(sock_fd, backlog);
}
```

### Accept

Once we have marked the socket as a `LISTEN`ing socket, we call `accept` on it.

```c

void server() {
.
    for (;;) {
	ret = accept(sockfd, addr, addrlen);
    }
.
}

```

```c
int inet_accept(struct socket *sock, struct socket *newsock,
		struct proto_accept_arg *arg)
{
	struct sock *sk1 = sock->sk, *sk2;

	/* IPV6_ADDRFORM can change sk->sk_prot under us. */
	arg->err = -EINVAL;
	sk2 = READ_ONCE(sk1->sk_prot)->accept(sk1, arg);
	if (!sk2)
		return arg->err;

	lock_sock(sk2);
	__inet_accept(sock, newsock, sk2);
	release_sock(sk2);
	return 0;
}

```
Figure X. `accept` for `AF_INET` is implemented in `inet_accept`.


For TCP, the `accept` callback is registered to `inet_csk_accept` in [`net/tcp_ipv4.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_ipv4.c)

```c
struct proto tcp_prot = {
	.name			= "TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.pre_connect		= tcp_v4_pre_connect,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,

```
Figure X. TCP implementation of `accept` system call.

TCPs accept call ultimately generates a new socket.

```c


/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{

}


/*
 * This will accept the next outstanding connection.
 */
struct sock *inet_csk_accept(struct sock *sk, struct proto_accept_arg *arg)
{

	/* Find already established connection */
	if (reqsk_queue_empty(queue)) {
		long timeo = sock_rcvtimeo(sk, arg->flags & O_NONBLOCK);

		error = inet_csk_wait_for_connect(sk, timeo);
```

### Listen

The listen system call is implemented using the following kernel datastructures and functions. 

```c

const struct proto_ops inet_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,

	.listen		   = inet_listen,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
```
Figure X. Data stuctures for `PROTO_STREAM`/TCP sockets as defined in [`net/af_inet.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L1052)


```c
/*
 *	Move a socket into listening state.
 */
int inet_listen(struct socket *sock, int backlog)
{

```
Figure `listen` for `AF_NET` is implemented in [`af_inet.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c#L252)


The `inet_connection_sock_af_ops` struct `ipv4_specific` contains callback functions for 
processing received tcp packets. The `conn\_request` member is eventually called be the
Linux `socket` is in the `LISTEN` state, per the comments.
