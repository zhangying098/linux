/* This test is a demo of using get_socket_uid and get_socket_cookie
 * helper function to do per socket based network traffic monitoring.
 * It requires iptables version higher then 1.6.1. to load pinned eBPF
 * program into the xt_bpf match.
 *
 * TEST:
 * ./run_cookie_uid_helper_example.sh -option
 * option:
 *	-t: do traffic monitoring test, the program will continuously
 * print out network traffic happens after program started A sample
 * output is shown below:
 *
 * cookie: 877, uid: 0x3e8, Pakcet Count: 20, Bytes Count: 11058
 * cookie: 132, uid: 0x0, Pakcet Count: 2, Bytes Count: 286
 * cookie: 812, uid: 0x3e8, Pakcet Count: 3, Bytes Count: 1726
 * cookie: 802, uid: 0x3e8, Pakcet Count: 2, Bytes Count: 104
 * cookie: 877, uid: 0x3e8, Pakcet Count: 20, Bytes Count: 11058
 * cookie: 831, uid: 0x3e8, Pakcet Count: 2, Bytes Count: 104
 * cookie: 0, uid: 0x0, Pakcet Count: 6, Bytes Count: 712
 * cookie: 880, uid: 0xfffe, Pakcet Count: 1, Bytes Count: 70
 *
 *	-s: do getsockopt SO_COOKIE test, the program will set up a pair of
 * UDP sockets and send packets between them. And read out the traffic data
 * directly from the ebpf map based on the socket cookie.
 *
 * Clean up: if using shell script, the script file will delete the iptables
 * rule and unmount the bpf program when exit. Else the iptables rule need
 * to be deleted by hand, see run_cookie_uid_helper_example.sh for detail.
 */

#define _GNU_SOURCE

#define offsetof(type, member) __builtin_offsetof(type, member)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"

#define PORT 8888

struct stats {
	uint32_t uid;
	uint64_t packets;
	uint64_t bytes;
};

static int map_fd, prog_fd;

static bool test_finish;

/*
	功能：
		调用 bpf_map_create 创建一个映射，返回文件描述符
	bpf_map_create 使用方法：
		LIBBPF_API int bpf_map_create (enum bpf_map_type map_type, 
			onst char *map_name, __u32 key_size, __u32 value_size, __u32 max_entries, 
			const struct bpf_map_create_opts *opts)
*/
static void maps_create(void)
{
	map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(uint32_t),
				sizeof(struct stats), 100, NULL);
	if (map_fd < 0)
		error(1, errno, "map create failed!\n");
}

/*
	这部分的 epbf insn 改写成 epbf prog 形式：
	
	#include <linux/bpf.h>
	#include <linux/if_ether.h>
	#include <linux/ip.h>
	#include <linux/in.h>

	struct bpf_map_def SEC("maps") stats_map = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(struct sock_key),
		.value_size = sizeof(struct stats),
		.max_entries = 1024,
	};

	SEC("socket")
	int bpf_prog(struct __sk_buff *skb)
	{
		struct sock_key key = {};
		struct stats *stats, zero = {};
		u64 socket_cookie;
		u32 uid;

		bpf_get_socket_cookie(skb, &socket_cookie);
		bpf_map_update_elem(&stats_map, &socket_cookie, &zero, BPF_NOEXIST);

		stats = bpf_map_lookup_elem(&stats_map, &socket_cookie);
		if (!stats)
			return 0;

		uid = bpf_get_socket_uid(skb);
		stats->uid = uid;
		stats->packets = +1;
		stats->bytes = +skb->len;

		bpf_map_update_elem(&stats_map, &socket_cookie, stats, BPF_EXIST);

		return 0;
	}

	char _license[] SEC("license") = "GPL";
*/
static void prog_load(void)
{
	static char log_buf[1 << 16];

	/*
		对网络数据包进行统计，并将统计结果存储到一个eBPF map中
	*/
	struct bpf_insn prog[] = {
		/*
		 * Save sk_buff for future usage. value stored in R6 to R10 will
		 * not be reset after a bpf helper function call.
		 */
		/*
			BPF_MOV64_REG 宏功能：
				将寄存器 BPF_REG_1 值移动到寄存器 BPF_REG_6 中
			当调用一个 BPF 辅助函数后，寄存器 R6 - R10 的值不会被重置或清除。
			（当前 BPF 辅助函数最多的入参是5个）
			此处目的是将 sk_buff保存起来，供后续操作使用。
		*/
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		/*
		 * pc1: BPF_FUNC_get_socket_cookie takes one parameter,
		 * R1: sk_buff
		 */
		/*
			调用BPF_FUNC_get_socket_cookie函数，获取套接字的cookie
			该函数需要一个参数，该参数来自于 R1 寄存器的 SK_BUFF
			
			#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
				((struct bpf_insn) {					\
					.code  = CODE,					\
					.dst_reg = DST,					\
					.src_reg = SRC,					\
					.off   = OFF,					\
					.imm   = IMM })

			CODE: 指令的类型
			DST：目标寄存器的索引或标识符
			SRC：源寄存器的索引或标识符
			OFF：偏移量
			IMM：立即数，这里是函数 index
		*/
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_get_socket_cookie),
		/* pc2-4: save &socketCookie to r7 for future usage*/
		/*
			将寄存器存储到内存中

			BPF_DW： 存储的数据宽度双字（8字节）
			BPF_REG_10 是目标内存地址的基址寄存器，BPF_REG_0 是源寄存器，用于提供要存储的值
			-8: 表示从基址寄存器所指定的地址向前偏移8个字节
		*/
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		// 将 BPF_REG_0 寄存器的值保存到BPF_REG_10 中
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
		/*
			BPF_ALU64_IMM： 对寄存器的值执行算术运算

				BPF_ADD： 执行加法运算
				BPF_REG_7：目标寄存器，存储计算结果
				-8: 立即数，与寄存器值想加的值
		*/
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -8),
		/*
		 * pc5-8: set up the registers for BPF_FUNC_map_lookup_elem,
		 * it takes two parameters (R1: map_fd,  R2: &socket_cookie)
		 */
		// 加载 map fd 到指定寄存器
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
		// 调用 map_lookup_elem 函数
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_map_lookup_elem),
		/*
		 * pc9. if r0 != 0x0, go to pc+14, since we have the cookie
		 * stored already
		 * Otherwise do pc10-22 to setup a new data entry.
		 */
		// pc， BPF_REG_0 保存的值不定于 0， 则跳转到 pc + 14 位置，存储有 cookie
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 14),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_get_socket_uid),
		/*
		 * Place a struct stats in the R10 stack and sequentially
		 * place the member value into the memory. Packets value
		 * is set by directly place a IMM value 1 into the stack.
		 */
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
			    -32 + (__s16)offsetof(struct stats, uid)),
		BPF_ST_MEM(BPF_DW, BPF_REG_10,
			   -32 + (__s16)offsetof(struct stats, packets), 1),
		/*
		 * __sk_buff is a special struct used for eBPF program to
		 * directly access some sk_buff field.
		 */
		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6,
			    offsetof(struct __sk_buff, len)),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1,
			    -32 + (__s16)offsetof(struct stats, bytes)),
		/*
		 * add new map entry using BPF_FUNC_map_update_elem, it takes
		 * 4 parameters (R1: map_fd, R2: &socket_cookie, R3: &stats,
		 * R4: flags)
		 */
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -32),
		BPF_MOV64_IMM(BPF_REG_4, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_map_update_elem),
		BPF_JMP_IMM(BPF_JA, 0, 0, 5),
		/*
		 * pc24-30 update the packet info to a exist data entry, it can
		 * be done by directly write to pointers instead of using
		 * BPF_FUNC_map_update_elem helper function
		 */
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),
		BPF_MOV64_IMM(BPF_REG_1, 1),
		BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_9, BPF_REG_1,
			      offsetof(struct stats, packets)),
		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6,
			    offsetof(struct __sk_buff, len)),
		BPF_ATOMIC_OP(BPF_DW, BPF_ADD, BPF_REG_9, BPF_REG_1,
			      offsetof(struct stats, bytes)),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6,
			    offsetof(struct __sk_buff, len)),
		BPF_EXIT_INSN(),
	};
	/*
		LIBBPF_OPTS 功能： 
			生命结构体，并赋值
		
		struct bpf_prog_load_opts opts = {
			.log_buf = log_buf,
			.log_size = sizeof(log_buf),
		}
	*/
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_buf = log_buf,
		    .log_size = sizeof(log_buf), );

	/*
		bpf_prog_load 加载 ebpf prog 返回 prog_fd

		param:
			BPF_PROG_TYPE_SOCKET_FILTER 要加载的 ebpf 程序类型，套接字过滤器程序类型，套接字操作期间执行过滤操作
			prog: 这是要加载的eBPF程序的指令数组的指针，包含了要执行的eBPF指令。
			ARRAY_SIZE(prog): 这是指令数组prog的大小，表示包含了多少个指令。
			&opts: 这是指向之前初始化的bpf_prog_load_opts结构体变量opts的指针，用于传递加载选项。
	*/
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", prog,
				ARRAY_SIZE(prog), &opts);
	if (prog_fd < 0)
		error(1, errno, "failed to load prog\n%s\n", log_buf);
}

//  将一个BPF程序附加到iptables规则中
static void prog_attach_iptables(char *file)
{
	// 用于存储函数返回值或临时结果的整型变量
	int ret;
	// 存储iptables规则的字符数组，长度为256
	char rules[256];

	// 将BPF对象固定到文件系统中
	if (bpf_obj_pin(prog_fd, file))
		error(1, errno, "bpf_obj_pin");
	// 检查文件路径是否超过50个字符，如果是则输出错误信息并退出程序
	if (strlen(file) > 50) {
		printf("file path too long: %s\n", file);
		exit(1);
	}
	// 构造iptables命令，并将结果存储在rules数组中
	/*
		iptablesd 命令功能：BPF对象附加到iptables的OUTPUT链上，并允许匹配到该对象的数据包通过防火墙
			-A OUTPUT: -A选项表示在指定链（这里是OUTPUT链）的末尾添加一条规则
			-m bpf: -m选项表示使用特定的扩展模块，这里是bpf模块，用于与BPF相关的操作
			--object-pinned %s: --object-pinned选项指定了一个BPF对象的路径，该对象被固定到了文件系统中。%s将被实际的文件路径替换
			-j ACCEPT: -j选项表示如果数据包匹配到了此规则，应该执行的动作。这里的动作是接受（ACCEPT）匹配到的数据包，允许其通过防火墙
	*/
	ret = snprintf(rules, sizeof(rules),
		       "iptables -A OUTPUT -m bpf --object-pinned %s -j ACCEPT",
		       file);
	if (ret < 0 || ret >= sizeof(rules)) {
		printf("error constructing iptables command\n");
		exit(1);
	}
	// 执行命令
	ret = system(rules);
	if (ret < 0) {
		printf("iptables rule update failed: %d/n", WEXITSTATUS(ret));
		exit(1);
	}
}

static void print_table(void)
{
	struct stats curEntry;
	uint32_t curN = UINT32_MAX;
	uint32_t nextN;
	int res;

	// 使用bpf_map_get_next_key函数遍历映射中的所有键值对
	while (bpf_map_get_next_key(map_fd, &curN, &nextN) > -1) {
		curN = nextN;
		// 根据 key 获取 value(curEntry) 值
		res = bpf_map_lookup_elem(map_fd, &curN, &curEntry);
		if (res < 0) {
			error(1, errno, "fail to get entry value of Key: %u\n",
			      curN);
		} else {
			printf("cookie: %u, uid: 0x%x, Packet Count: %lu,"
			       " Bytes Count: %lu\n",
			       curN, curEntry.uid, curEntry.packets,
			       curEntry.bytes);
		}
	}
}

static void udp_client(void)
{
	struct sockaddr_in si_other = { 0 }; // 远程主机地址
	struct sockaddr_in si_me = { 0 }; // 本地主机地址
	struct stats dataEntry; // 存储从BPF映射中获取的数据
	int s_rcv, s_send, i,
		recv_len; // 接收和发送套接字，循环计数器，接收消息长度
	char message = 'a'; // 发送的消息内容
	char buf; // 接收消息的缓冲区
	uint64_t cookie; // 用于获取套接字标识符（cookie）
	int res; // 存储函数调用结果
	socklen_t cookie_len = sizeof(cookie); // cookie长度
	socklen_t slen = sizeof(si_other); // 地址结构体长度

	// 创建接收套接字， PT_INET： 指定 IPV4协议；SOCK_DGRAM：套接字类型，这里是数据报套接字； 0 表示默认协议，这里默认传输层IPV4,UDP
	s_rcv = socket(PF_INET, SOCK_DGRAM, 0);
	if (s_rcv < 0)
		error(1, errno, "rcv socket creat failed!\n");
	// 设置远程主机协议族、端口号
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	// 将字符串形式的 IPv4 地址转换为二进制形式，并存储到 si_other.sin_addr 成员中
	if (inet_aton("127.0.0.1", &si_other.sin_addr) == 0)
		error(1, errno, "inet_aton\n");
	// 将接收套接字绑定到主机地址
	if (bind(s_rcv, (struct sockaddr *)&si_other, sizeof(si_other)) == -1)
		error(1, errno, "bind\n");
	// 创建发送套接字
	s_send = socket(PF_INET, SOCK_DGRAM, 0);
	if (s_send < 0)
		error(1, errno, "send socket creat failed!\n");
	// 获取发送套接字的cookie
	res = getsockopt(s_send, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_len);
	if (res < 0)
		printf("get cookie failed: %s\n", strerror(errno));
	res = bpf_map_lookup_elem(map_fd, &cookie, &dataEntry);
	if (res != -1)
		error(1, errno, "socket stat found while flow not active\n");
	// 发送和接收消息，循环10次
	for (i = 0; i < 10; i++) {
		// 发送消息
		res = sendto(s_send, &message, sizeof(message), 0,
			     (struct sockaddr *)&si_other, slen);
		if (res == -1)
			error(1, errno, "send\n");
		if (res != sizeof(message))
			error(1, 0, "%uB != %luB\n", res, sizeof(message));

		// 接收消息
		/*
			sockfd: 这是已经创建并绑定的套接字的文件描述符。
			buf: 这是一个指向缓冲区的指针，用于存储接收到的数据。
			len: 这是缓冲区 buf 的大小，以字节为单位。
			flags: 这是一些标志位，用于修改 recvfrom 的行为。例如，MSG_DONTWAIT 表示非阻塞模式，MSG_WAITALL 表示等待直到接收到指定长度的数据。
			src_addr: 这是一个指向 sockaddr 结构体的指针，用于存储发送方的地址信息。如果不需要获取发送方的地址，可以设置为 NULL。
			addrlen: 这是一个指向整型的指针，用于指定 src_addr 结构体的大小。在调用 recvfrom 之前，应该将其设置为 src_addr 结构体的大小，在调用之后，它将被设置为新接收到的地址的实际大小。
			返回值：
				如果成功，recvfrom 返回接收到的字节数。
				如果连接被对方优雅地关闭，返回 0。
				如果发生错误，返回 -1，并设置全局变量 errno 来指示错误的原因。
				使用 recvfrom 时，需要处理可能出现的各种错误情况，例如，如果套接字处于非阻塞模式并且没有数据可读，recvfrom 可能会返回 EAGAIN 或 EWOULDBLOCK 错误。
		*/
		recv_len = recvfrom(s_rcv, &buf, sizeof(buf), 0,
				    (struct sockaddr *)&si_me, &slen);
		if (recv_len < 0)
			error(1, errno, "receive\n");
		res = memcmp(&(si_other.sin_addr), &(si_me.sin_addr),
			     sizeof(si_me.sin_addr));
		if (res != 0)
			error(1, EFAULT, "sender addr error: %d\n", res);
		printf("Message received: %c\n", buf);
		res = bpf_map_lookup_elem(map_fd, &cookie, &dataEntry);
		if (res < 0)
			error(1, errno, "lookup sk stat failed, cookie: %lu\n",
			      cookie);
		printf("cookie: %lu, uid: 0x%x, Packet Count: %lu,"
		       " Bytes Count: %lu\n\n",
		       cookie, dataEntry.uid, dataEntry.packets,
		       dataEntry.bytes);
	}
	close(s_send);
	close(s_rcv);
}

/*
	帮助函数；
		-t 进行流量监控测试
		-s 进行获取sockopt cookie测试
	命令行演示：
		./run_cookie_uid_helper_example.sh my_bpf_program -t
		./run_cookie_uid_helper_example.sh my_bpf_program -s
*/
static int usage(void)
{
	printf("Usage: ./run_cookie_uid_helper_example.sh"
	       " bpfObjName -option\n"
	       "	-t	traffic monitor test\n"
	       "	-s	getsockopt cookie test\n");
	return 1;
}

static void finish(int ret)
{
	test_finish = true;
}

int main(int argc, char *argv[])
{
	int opt;
	// 是 流量监控 还是 进行获取sockopt cookie
	bool cfg_test_traffic = false;
	bool cfg_test_cookie = false;

	if (argc != 3)
		return usage();

	// getopt 函数进行参数解析
	while ((opt = getopt(argc, argv, "ts")) != -1) {
		switch (opt) {
		case 't':
			cfg_test_traffic = true;
			break;
		case 's':
			cfg_test_cookie = true;
			break;

		default:
			printf("unknown option %c\n", opt);
			usage();
			return -1;
		}
	}
	maps_create();
	prog_load();
	prog_attach_iptables(argv[2]);
	if (cfg_test_traffic) {
		// 注册信号处理函数，当接收到SIGINT信号（通常由按下Ctrl+C触发）时执行finish函数
		if (signal(SIGINT, finish) == SIG_ERR)
			error(1, errno, "register SIGINT handler failed");
		// 注册信号处理函数，当接收到SIGTERM信号时执行finish函数
		if (signal(SIGTERM, finish) == SIG_ERR)
			error(1, errno, "register SIGTERM handler failed");
		// test_finish 由 finish 函数调控
		while (!test_finish) {
			print_table();
			printf("\n");
			sleep(1);
		}
	} else if (cfg_test_cookie) {
		udp_client();
	}
	close(prog_fd);
	close(map_fd);
	return 0;
}
