#include <linux/unistd.h>
#include <linux/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h>
#include "bpf_insn.h"
#include "sock_example.h"
#include "bpf_util.h"

#define BPF_F_PIN (1 << 0)
#define BPF_F_GET (1 << 1)
#define BPF_F_PIN_GET (BPF_F_PIN | BPF_F_GET)

#define BPF_F_KEY (1 << 2)
#define BPF_F_VAL (1 << 3)
#define BPF_F_KEY_VAL (BPF_F_KEY | BPF_F_VAL)

#define BPF_M_UNSPEC 0
#define BPF_M_MAP 1
#define BPF_M_PROG 2

char bpf_log_buf[BPF_LOG_BUF_SIZE];

static void usage(void)
{
	printf("Usage: fds_example [...]\n");
	printf("       -F <file>   File to pin/get object\n");
	printf("       -P          |- pin object\n");
	printf("       -G          `- get object\n");
	printf("       -m          eBPF map mode\n");
	printf("       -k <key>    |- map key\n");
	printf("       -v <value>  `- map value\n");
	printf("       -p          eBPF prog mode\n");
	printf("       -o <object> `- object file\n");
	printf("       -h          Display this help.\n");
}

static int bpf_prog_create(const char *object)
{
	// 初始化 BPF 指令集
	static struct bpf_insn insns[] = {
		// 将立即数1加载到寄存器0中
		BPF_MOV64_IMM(BPF_REG_0, 1),
		// 退出 BPF 程序
		BPF_EXIT_INSN(),
	};
	// 统计 BPF 指令数量
	size_t insns_cnt = ARRAY_SIZE(insns);
	struct bpf_object *obj;
	int err;

	if (object) {
		// 打开指定的BPF对象文件，并加载该文件
		obj = bpf_object__open_file(object, NULL);
		assert(!libbpf_get_error(obj));
		// 加载BPF对象文件
		err = bpf_object__load(obj);
		assert(!err);
		// 返回加载的程序的文件描述符
		return bpf_program__fd(bpf_object__next_program(obj, NULL));
	} else {
		// 如果传入的object参数为空，则直接加载内联的BPF程序

		// 定义加载BPF程序的选项，并设置日志缓冲区和大小
		LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_buf = bpf_log_buf,
			    .log_size = BPF_LOG_BUF_SIZE, );
		// 加载内联的BPF程序，指定程序类型为SOCKET_FILTER，许可证类型为GPL
		return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
				     insns, insns_cnt, &opts);
	}
}

static int bpf_do_map(const char *file, uint32_t flags, uint32_t key,
		      uint32_t value)
{
	int fd, ret;

	if (flags & BPF_F_PIN) {
		/*
			创建 ebpf map;

			int bpf_map_create(enum bpf_map_type map_type,
					const char *map_name,
					__u32 key_size,
					__u32 value_size,
					__u32 max_entries,
					const struct bpf_map_create_opts *opts)
		*/
		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, sizeof(uint32_t),
				    sizeof(uint32_t), 1024, NULL);
		printf("bpf: map fd:%d (%s)\n", fd, strerror(errno));
		assert(fd > 0);

		// 将 ebpf map fd 绑定到文件系统中指定的文件
		ret = bpf_obj_pin(fd, file);
		printf("bpf: pin ret:(%d,%s)\n", ret, strerror(errno));
		assert(ret == 0);
	} else {
		// 从文件中获取 ebpf map fd
		fd = bpf_obj_get(file);
		printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
		assert(fd > 0);
	}

	if ((flags & BPF_F_KEY_VAL) == BPF_F_KEY_VAL) {
		// 更新 ebpf map 的 value 值
		ret = bpf_map_update_elem(fd, &key, &value, 0);
		printf("bpf: fd:%d u->(%u:%u) ret:(%d,%s)\n", fd, key, value,
		       ret, strerror(errno));
		assert(ret == 0);
	} else if (flags & BPF_F_KEY) {
		// 根据 key 查询 value 值
		ret = bpf_map_lookup_elem(fd, &key, &value);
		printf("bpf: fd:%d l->(%u):%u ret:(%d,%s)\n", fd, key, value,
		       ret, strerror(errno));
		assert(ret == 0);
	}

	return 0;
}

static int bpf_do_prog(const char *file, uint32_t flags, const char *object)
{
	int fd, sock, ret;

	if (flags & BPF_F_PIN) {
		// 创建 ebpf prog，加载到内核
		fd = bpf_prog_create(object);
		printf("bpf: prog fd:%d (%s)\n", fd, strerror(errno));
		assert(fd > 0);

		// 将 ebpf prog 绑定到 bpffd file 上
		ret = bpf_obj_pin(fd, file);
		printf("bpf: pin ret:(%d,%s)\n", ret, strerror(errno));
		assert(ret == 0);
	} else {
		// 从文件中获取 ebpf prog fd
		fd = bpf_obj_get(file);
		printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
		assert(fd > 0);
	}

	sock = open_raw_sock("lo");
	assert(sock > 0);

	// 将eBPF程序关联到原始套接字上
	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
	printf("bpf: sock:%d <- fd:%d attached ret:(%d,%s)\n", sock, fd, ret,
	       strerror(errno));
	assert(ret == 0);

	return 0;
}

int main(int argc, char **argv)
{
	const char *file = NULL, *object = NULL;
	uint32_t key = 0, value = 0, flags = 0;
	int opt, mode = BPF_M_UNSPEC;

	while ((opt = getopt(argc, argv, "F:PGmk:v:po:")) != -1) {
		switch (opt) {
		/* General args */
		case 'F':
			// optarg 表示当前选项的参数值
			file = optarg;
			break;
		case 'P':
			flags |= BPF_F_PIN;
			break;
		case 'G':
			flags |= BPF_F_GET;
			break;
		/* Map-related args */
		case 'm':
			mode = BPF_M_MAP;
			break;
		case 'k':
			// 将 key 转为无符号长整型并存储在 Key 中
			key = strtoul(optarg, NULL, 0);
			flags |= BPF_F_KEY;
			break;
		case 'v':
			value = strtoul(optarg, NULL, 0);
			flags |= BPF_F_VAL;
			break;
		/* Prog-related args */
		case 'p':
			mode = BPF_M_PROG;
			break;
		case 'o':
			object = optarg;
			break;
		default:
			goto out;
		}
	}

	if (!(flags & BPF_F_PIN_GET) || !file)
		goto out;

	switch (mode) {
	case BPF_M_MAP:
		return bpf_do_map(file, flags, key, value);
	case BPF_M_PROG:
		return bpf_do_prog(file, flags, object);
	}
out:
	usage();
	return -1;
}
