#undef TRACE_SYSTEM
#define TRACE_SYSTEM oom

#if !defined(_TRACE_OOM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_OOM_H
#include <linux/tracepoint.h>

TRACE_EVENT(oom_score_adj_update,

	TP_PROTO(struct task_struct *task),

	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(	pid_t,	pid)
		__array(	char,	comm,	TASK_COMM_LEN )
		__field(	short,	oom_score_adj)
	),

	TP_fast_assign(
		__entry->pid = task->pid;
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->oom_score_adj = task->signal->oom_score_adj;
	),

	TP_printk("pid=%d comm=%s oom_score_adj=%hd",
		__entry->pid, __entry->comm, __entry->oom_score_adj)
);

TRACE_EVENT(mark_victim,

	TP_PROTO(struct task_struct *task),

	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(uid_t, uid)
		__array(char, comm, TASK_COMM_LEN)
		__field(unsigned long, total_vm)
		__field(unsigned long, anon_rss)
		__field(unsigned long, file_rss)
	),

	TP_fast_assign(
		__entry->pid = task->pid;
		__entry->uid = from_kuid(&init_user_ns, task_uid(task));
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->total_vm = task->mm->total_vm;
		__entry->anon_rss = get_mm_counter(task->mm, MM_ANONPAGES);
		__entry->file_rss = get_mm_counter(task->mm, MM_FILEPAGES);
	),

	TP_printk("pid=%d uid=%d comm=%s total-vm=%lukB anon-rss=%lukB file-rss=%lukB",
		__entry->pid, __entry->uid, __entry->comm,
		__entry->total_vm << (PAGE_SHIFT - 10),
		__entry->anon_rss << (PAGE_SHIFT - 10),
		__entry->file_rss << (PAGE_SHIFT - 10))
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
