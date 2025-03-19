/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched = true;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

/**
 * @brief Increments the counter in the stats map for the given index.
 *
 * This function looks up the counter at the specified index in the stats map and,
 * if found, increments its value by one. No action is taken if the index is not present.
 *
 * @param idx Index into the stats map corresponding to the desired counter.
 */
static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

/**
 * @brief Selects a CPU for the task and enqueues it for local dispatch if the CPU is idle.
 *
 * This function calls the scheduler's default CPU selection routine to determine the
 * appropriate CPU for a given task. If the selected CPU is idle, it registers the event
 * by incrementing the local queue count and inserting the task into the local dispatch queue.
 *
 * @param p Pointer to the task structure to be scheduled.
 * @param prev_cpu Identifier of the previous CPU on which the task was running.
 * @param wake_flags Flags indicating the wake-up conditions for the task.
 * @return s32 The identifier of the selected CPU.
 */
s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle) {
        stat_inc(0); /* count local queueing */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

/**
 * @brief Enqueues a task into the global dispatch queue.
 *
 * This function first increments the global queueing statistic, then enqueues the task
 * based on the scheduler mode. In FIFO mode, the task is inserted directly into the shared
 * dispatch queue using default slicing. In virtual time mode, the task's virtual time is
 * adjusted—limiting its lag to one slice behind the current global virtual time—before it is
 * enqueued with its virtual time value.
 *
 * @param p Pointer to the task structure to be enqueued.
 * @param enq_flags Flags that modify the behavior of the enqueue operation.
 */
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1); /* count global queueing */

    if (fifo_sched) {
        scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    } else {
        u64 vtime = p->scx.dsq_vtime;

        /*
         * Limit the amount of budget that an idling task can accumulate
         * to one slice.
         */
        if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
            vtime = vtime_now - SCX_SLICE_DFL;

        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
    }
}

/**
 * @brief Dispatch tasks into the local queue.
 *
 * This function moves tasks from the shared dispatch queue to the local dispatch queue,
 * facilitating task scheduling on a specific CPU. The parameters are included for interface
 * compatibility but are not used in this implementation.
 *
 * @param cpu Unused parameter required by the operations interface.
 * @param prev Unused parameter required by the operations interface.
 */
void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

/**
 * @brief Updates the global virtual time based on the task's dispatch queue virtual time.
 *
 * When FIFO scheduling is disabled, this function checks if the task's dispatch queue
 * virtual time is ahead of the global virtual time and updates the global virtual time accordingly.
 * If FIFO scheduling is enabled, no update is performed.
 *
 * @param p Pointer to the task structure containing the dispatch queue virtual time.
 */
void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    if (fifo_sched)
        return;

    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (time_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

/**
 * @brief Updates a task's virtual time allocation when it stops running.
 *
 * If FIFO scheduling is disabled, this function increments the task's virtual time
 * (dsq_vtime) by scaling the remaining portion of its default time slice via its weight.
 * This adjustment reflects the consumed slice of the task, factoring in that tasks which yield
 * may have their entire slice deducted (as p->scx.slice is reset to zero). If FIFO scheduling is
 * enabled, no scaling is performed.
 *
 * @param p Pointer to the task structure whose virtual time is being updated.
 * @param runnable Indicates whether the task remains runnable after stopping (currently unused).
 */
void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    if (fifo_sched)
        return;

    /*
     * Scale the execution time by the inverse of the weight and charge.
     *
     * Note that the default yield implementation yields by setting
     * @p->scx.slice to zero and the following would treat the yielding task
     * as if it has consumed all its slice. If this penalizes yielding tasks
     * too much, determine the execution time by taking explicit timestamps
     * instead of depending on @p->scx.slice.
     */
    p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

/**
 * @brief Initializes a task's virtual scheduling time.
 *
 * Sets the task's dispatch queue virtual time to the current global virtual time,
 * thereby preparing the task for scheduling.
 *
 * @param p Pointer to the task whose virtual time is being initialized.
 */
void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}

/**
 * @brief Initializes the shared dispatch queue.
 *
 * This function creates the shared dispatch queue by calling scx_bpf_create_dsq
 * with the shared dispatch queue identifier and a CPU parameter of -1, indicating
 * a global or default CPU configuration.
 *
 * @return s32 The identifier of the created dispatch queue, or a negative error code on failure.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

/**
 * @brief Records a task exit event.
 *
 * This function logs the exit event for a task by recording the provided exit
 * information with the UEI mechanism, thereby notifying userspace of the termination.
 *
 * @param ei Pointer to the exit event information structure.
 */
void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
               .select_cpu = (void *) simple_select_cpu,
               .enqueue = (void *) simple_enqueue,
               .dispatch = (void *) simple_dispatch,
               .running = (void *) simple_running,
               .stopping = (void *) simple_stopping,
               .enable = (void *) simple_enable,
               .init = (void *) simple_init,
               .exit = (void *) simple_exit,
               .name = "simple");
