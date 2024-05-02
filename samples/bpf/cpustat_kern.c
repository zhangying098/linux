// SPDX-License-Identifier: GPL-2.0

#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * The CPU number, cstate number and pstate number are based
 * on 96boards Hikey with octa CA53 CPUs.
 *
 * Every CPU have three idle states for cstate:
 *   WFI, CPU_OFF, CLUSTER_OFF
 *
 * Every CPU have 5 operating points:
 *   208MHz, 432MHz, 729MHz, 960MHz, 1200MHz
 *
 * This code is based on these assumption and other platforms
 * need to adjust these definitions.s
 */
#define MAX_CPU 8
#define MAX_PSTATE_ENTRIES 5
#define MAX_CSTATE_ENTRIES 3

static int cpu_opps[] = { 208000, 432000, 729000, 960000, 1200000 };

/*
 * my_map structure is used to record cstate and pstate index and
 * timestamp (Idx, Ts), when new event incoming we need to update
 * combination for new state index and timestamp (Idx`, Ts`).
 *
 * Based on (Idx, Ts) and (Idx`, Ts`) we can calculate the time
 * interval for the previous state: Duration(Idx) = Ts` - Ts.
 *
 * Every CPU has one below array for recording state index and
 * timestamp, and record for cstate and pstate saperately:
 *
 * +--------------------------+
 * | cstate timestamp         |
 * +--------------------------+
 * | cstate index             |
 * +--------------------------+
 * | pstate timestamp         |
 * +--------------------------+
 * | pstate index             |
 * +--------------------------+
 */

/*
my_map 的结构，用于记录 cstate 和 pstate 的索引以及时间戳。当新的事件发生时，需要更新新状态索引和时间戳的组合。
基于前后两个状态索引和时间戳，可以计算出前一个状态的持续时间。

每个 CPU 都有一个类似下面描述的数组，用于记录状态索引和时间戳，分别记录 cstate 和 pstate：

	cstate 时间戳：记录 cstate 的时间戳，表示 cstate 最后一次改变的时间。
	cstate 索引：记录当前的 cstate 索引，表示当前 CPU 的 cstate 状态。

	pstate 时间戳：记录 pstate 的时间戳，表示 pstate 最后一次改变的时间。
	pstate 索引：记录当前的 pstate 索引，表示当前 CPU 的 pstate 状态。
*/
// cstate 时间戳
#define MAP_OFF_CSTATE_TIME 0
// cstate 频率
#define MAP_OFF_CSTATE_IDX 1
// pstate 时间戳
#define MAP_OFF_PSTATE_TIME 2
// pstate 频率
#define MAP_OFF_PSTATE_IDX 3
#define MAP_OFF_NUM 4

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_CPU *MAP_OFF_NUM);
} my_map SEC(".maps");

/* cstate_duration records duration time for every idle state per CPU */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_CPU *MAX_CSTATE_ENTRIES);
} cstate_duration SEC(".maps");

/* pstate_duration records duration time for every operating point per CPU */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_CPU *MAX_PSTATE_ENTRIES);
} pstate_duration SEC(".maps");

/*
 * The trace events for cpu_idle and cpu_frequency are taken from:
 * /sys/kernel/tracing/events/power/cpu_idle/format
 * /sys/kernel/tracing/events/power/cpu_frequency/format
 *
 * These two events have same format, so define one common structure.
 */
struct cpu_args {
	u64 pad;
	u32 state;
	u32 cpu_id;
};

/* calculate pstate index, returns MAX_PSTATE_ENTRIES for failure */
// 计算给定频率的索引 index
static u32 find_cpu_pstate_idx(u32 frequency)
{
	u32 i;

	for (i = 0; i < sizeof(cpu_opps) / sizeof(u32); i++) {
		if (frequency == cpu_opps[i])
			return i;
	}

	return i;
}

SEC("tracepoint/power/cpu_idle")
int bpf_prog1(struct cpu_args *ctx)
{
	u64 *cts, *pts, *cstate, *pstate, prev_state, cur_ts, delta;
	u32 key, cpu, pstate_idx;
	u64 *val;

	if (ctx->cpu_id > MAX_CPU)
		return 0;

	cpu = ctx->cpu_id;

	key = cpu * MAP_OFF_NUM + MAP_OFF_CSTATE_TIME;
	cts = bpf_map_lookup_elem(&my_map, &key);
	if (!cts)
		return 0;

	key = cpu * MAP_OFF_NUM + MAP_OFF_CSTATE_IDX;
	cstate = bpf_map_lookup_elem(&my_map, &key);
	if (!cstate)
		return 0;

	key = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_TIME;
	pts = bpf_map_lookup_elem(&my_map, &key);
	if (!pts)
		return 0;

	key = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_IDX;
	pstate = bpf_map_lookup_elem(&my_map, &key);
	if (!pstate)
		return 0;

	prev_state = *cstate;
	*cstate = ctx->state;

	if (!*cts) {
		*cts = bpf_ktime_get_ns();
		return 0;
	}

	cur_ts = bpf_ktime_get_ns();
	delta = cur_ts - *cts;
	*cts = cur_ts;

	/*
	 * When state doesn't equal to (u32)-1, the cpu will enter
	 * one idle state; for this case we need to record interval
	 * for the pstate.
	 *
	 *                 OPP2
	 *            +---------------------+
	 *     OPP1   |                     |
	 *   ---------+                     |
	 *                                  |  Idle state
	 *                                  +---------------
	 *
	 *            |<- pstate duration ->|
	 *            ^                     ^
	 *           pts                  cur_ts
	 */
	if (ctx->state != (u32)-1) {
		/* record pstate after have first cpu_frequency event */
		if (!*pts)
			return 0;

		delta = cur_ts - *pts;

		pstate_idx = find_cpu_pstate_idx(*pstate);
		if (pstate_idx >= MAX_PSTATE_ENTRIES)
			return 0;

		key = cpu * MAX_PSTATE_ENTRIES + pstate_idx;
		val = bpf_map_lookup_elem(&pstate_duration, &key);
		if (val)
			__sync_fetch_and_add((long *)val, delta);

		/*
	 * When state equal to (u32)-1, the cpu just exits from one
	 * specific idle state; for this case we need to record
	 * interval for the pstate.
	 *
	 *       OPP2
	 *   -----------+
	 *              |                          OPP1
	 *              |                     +-----------
	 *              |     Idle state      |
	 *              +---------------------+
	 *
	 *              |<- cstate duration ->|
	 *              ^                     ^
	 *             cts                  cur_ts
	 */
	} else {
		key = cpu * MAX_CSTATE_ENTRIES + prev_state;
		val = bpf_map_lookup_elem(&cstate_duration, &key);
		if (val)
			__sync_fetch_and_add((long *)val, delta);
	}

	/* Update timestamp for pstate as new start time */
	if (*pts)
		*pts = cur_ts;

	return 0;
}

/*
	trace_cpu_frequency 事件通常由内核的 ftrace 框架记录，并且在 CPU 频率发生变化时触发:
		1、CPU 频率变化： 从节能模式切换到高性能模式
		2、调度器调度：将任务从一个CPU调度到另一个CPU，导致目标CPU频率发生变化
		3、电源管理策略变化，从节能模式切换到高性能模式，会导致 CPU 频率变化
*/
SEC("tracepoint/power/cpu_frequency")
int bpf_prog2(struct cpu_args *ctx)
{
	u64 *pts, *cstate, *pstate, cur_ts, delta;
	u32 key, cpu, pstate_idx;
	u64 *val;

	cpu = ctx->cpu_id;

	key = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_TIME;
	pts = bpf_map_lookup_elem(&my_map, &key);
	if (!pts)
		return 0;

	key = cpu * MAP_OFF_NUM + MAP_OFF_PSTATE_IDX;
	pstate = bpf_map_lookup_elem(&my_map, &key);
	if (!pstate)
		return 0;

	key = cpu * MAP_OFF_NUM + MAP_OFF_CSTATE_IDX;
	cstate = bpf_map_lookup_elem(&my_map, &key);
	if (!cstate)
		return 0;
	// 记录当前 pstate 频率
	*pstate = ctx->state;

	// 如果是第一次记录，则 *pts 没有数据，需要进行初始化
	if (!*pts) {
		*pts = bpf_ktime_get_ns();
		return 0;
	}

	// 计算 pstate 状态 A -> B 的时间间隔，并将当前时间赋值给 *pts
	cur_ts = bpf_ktime_get_ns();
	delta = cur_ts - *pts;
	*pts = cur_ts;

	/* When CPU is in idle, bail out to skip pstate statistics */
	//  CPU 处于空闲状态时跳过对 pstate 统计
	if (*cstate != (u32)(-1))
		return 0;

	/*
	 * The cpu changes to another different OPP (in below diagram
	 * change frequency from OPP3 to OPP1), need recording interval
	 * for previous frequency OPP3 and update timestamp as start
	 * time for new frequency OPP1.
	 *
	 *                 OPP3
	 *            +---------------------+
	 *     OPP2   |                     |
	 *   ---------+                     |
	 *                                  |    OPP1
	 *                                  +---------------
	 *
	 *           pts                  cur_ts
	 */
	pstate_idx = find_cpu_pstate_idx(*pstate);
	if (pstate_idx >= MAX_PSTATE_ENTRIES)
		return 0;

	key = cpu * MAX_PSTATE_ENTRIES + pstate_idx;
	val = bpf_map_lookup_elem(&pstate_duration, &key);
	if (val)
		__sync_fetch_and_add((long *)val, delta);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;