#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# 当前路径 samples/bpf
local_dir="$(pwd)"
# 退回到 samples
root_dir=$local_dir/../..
# 创建临时目录，并返回目录地址； -d 表示创建临时目录 --tmp 表示该目录创建在系统临时目录中
mnt_dir=$(mktemp -d --tmp)

on_exit() {
	# 卸载 iptables 规则
	iptables -D OUTPUT -m bpf --object-pinned ${mnt_dir}/bpf_prog -j ACCEPT
	# 解除挂载
	umount ${mnt_dir}
	# 删除目录
	rm -r ${mnt_dir}
}

# trap 功能： 捕获shell脚本中的信号，并在接收到信号时执行指定的命令或脚本
# 此处：在接收到 EXIT 信号执行 on_exit 函数。就是脚本退出时需要执行该函数
trap on_exit EXIT
# 挂载 bpf 文件系统
mount -t bpf bpf ${mnt_dir}
# para1: bpf_prog 路径 para2: 脚本第一个参数
./per_socket_stats_example ${mnt_dir}/bpf_prog $1
