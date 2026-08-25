// racemap: a kernel thread is signaled to self-terminate (send_sig()) and
// then torn down via kthread_stop(), with no get_task_struct() bracketing
// the sequence. If the kthread races ahead and exits/self-frees its
// task_struct between the send_sig() and the kthread_stop() call, the
// kthread_stop() dereferences an already-freed task_struct -- CWE-416
// UAF. get_task_struct() pins the task_struct's own refcount for the
// duration of the sequence; kthread_stop() internally still works
// correctly with an externally-held reference, and put_task_struct()
// afterward releases it.
//
// Ground truth: CVE-2026-46180, "wifi: brcmfmac: Fix potential
// use-after-free issue when stopping watchdog task" -- brcmf_sdio_bus_stop()
// and brcmf_sdio_remove() both called send_sig(SIGTERM, bus->watchdog_tsk,
// 1) immediately followed by kthread_stop(bus->watchdog_tsk) with no
// reference held; the watchdog task could exit and free itself in that
// window. Fixed by adding get_task_struct()/put_task_struct() around the
// sequence. (A closely related bug, CVE-2026-46187 in the rsi wifi
// driver, involves the SAME general "kthread lifetime race between
// self-exit and external-stop" family but through kthread_complete_and_exit()
// + a completion instead of a plain refcount -- too idiosyncratic a
// combination to fold into this same rule; see if a get_task_struct-based
// instance shows up elsewhere before building a second rule for that
// variant.)
//
// TREE-WIDE REVIEW (2026-08-25/26): 6 hits, all in drivers/target/iscsi/
// (LIO iSCSI target). Deep investigation (multi-function control-flow
// tracing) found this SAME bug class was already found and fixed in this
// exact subsystem in 2017: commit 5e0cf5e6c43b9e19fc0284f69e5cd2b4a47523b0
// ("iscsi-target: Always wait for kthread_should_stop() before kthread
// exit", stable v3.12+). That fix introduced the `conn_freed` flag and
// the `connection_exit` atomic gate in iscsit_take_action_for_
// connection_exit() (iscsi_target_erl0.c) specifically so that a thread
// only skips its own `while (!kthread_should_stop()) msleep(100);` exit
// gate when it has independently proven (by winning that atomic gate)
// that it is the one closing the connection -- in which case it only
// ever calls kthread_stop() on the OTHER thread, never itself, and that
// other thread is guaranteed to have LOST the gate and be safely parked
// in its own msleep loop. All 6 flagged call sites are covered by this
// architecture. Confirmed false positive: this rule sees the surface
// syntax (send_sig()+kthread_stop(), no get_task_struct()) but has no way
// to see the cross-function `conn_freed`/`connection_exit` protection a
// prior real fix specifically built for this exact case -- a clear
// example of why every hit needs manual/LLM verification, not just
// pattern matching. See POTENTIAL-FINDINGS.md for the full writeup.
//
// Detects: send_sig(sig, task, ...); ... kthread_stop(task); with no
// get_task_struct(task) call anywhere in the same function before the
// kthread_stop().
// Exonerates: get_task_struct(task) called before send_sig() (or between
// send_sig() and kthread_stop()).
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file kthread_stop_without_get_task.cocci -D report --dir <kernel>/drivers

virtual report

@race exists@
identifier func;
expression task, sig;
position p;
@@
  func(...)
  {
  ...
  when != get_task_struct(task)
  send_sig(sig, task, ...);
  ...
  when != get_task_struct(task)
  kthread_stop@p(task);
  ...
  }

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:kthread_task_struct" % (p[0].file, p[0].line)
)

@safe exists@
identifier func;
expression task, sig;
@@
  func(...)
  {
  ...
  get_task_struct(task);
  ...
  send_sig(sig, task, ...);
  ...
  kthread_stop(task);
  ...
  }
