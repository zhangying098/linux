/* SPDX-License-Identifier: GPL-2.0 */
#include <stdlib.h>
#include <stdio.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

// 创建一个原始套接字（raw socket）并绑定到指定的网络接口上
static inline int open_raw_sock(const char *name)
{
	// 定义原始套接字结构
	struct sockaddr_ll sll;
	int sock;

	/*
		SOCK_RAW: 这个标志表示创建的套接字是一个原始套接字，它允许用户程序直接访问网络层数据包，
		而不是经过协议栈的处理。使用原始套接字可以实现更底层的网络操作，如构造自定义协议的数据包
		或进行数据包捕获。

		SOCK_NONBLOCK: 这个标志表示创建的套接字是非阻塞的。在非阻塞模式下，套接字的I/O操作不会
		阻塞程序的执行，即使没有立即可用的数据也会立即返回，而不是等待数据准备好。这使得程序可以
		在等待I/O操作完成时执行其他任务，提高了程序的并发性能。

		SOCK_CLOEXEC: 这个标志表示在执行 exec 系统调用时关闭套接字。当程序调用 exec 执行其他程
		序时，该标志会使得被执行的程序继承的文件描述符不包括当前套接字，从而避免资源泄漏或不必要
		的资源占用
	*/

	// 创建一个原始套接字，使用非阻塞和关闭时执行exec的方式打开， htons(ETH_P_ALL) 设置了协议类型，表示接收所有类型的数据包
	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		      htons(ETH_P_ALL));
	if (sock < 0) {
		printf("cannot create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	// 设置地址族为AF_PACKET，表示使用基于数据链路层的套接字
	sll.sll_family = AF_PACKET;
	// 将网络接口名称转换为对应的接口索引
	sll.sll_ifindex = if_nametoindex(name);
	// 设置协议类型为ETH_P_ALL，表示接收所有类型的数据包
	sll.sll_protocol = htons(ETH_P_ALL);
	// 将套接字与指定的网络接口绑定
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}
	// 如果所有操作都成功，则返回创建的套接字
	return sock;
}
