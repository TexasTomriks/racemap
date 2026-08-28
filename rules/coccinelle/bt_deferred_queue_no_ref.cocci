// racemap: object handed to hci_cmd_sync_queue()'s deferred-work callback
// without a reference held across the enqueue.
//
// This is the exact shape of the confirmed, real bug in
// net/bluetooth/hci_conn.c's hci_enhanced_setup_sync() (fixed 2026-08-06,
// commit 42de40abe25d "Bluetooth: hci_conn: fix the SCO setup context
// lifetime") and its earlier-fixed sibling abort_conn_sync(): a bare
// `struct hci_conn *` is stored into a wrapper struct and queued via
// hci_cmd_sync_queue() for deferred/async execution, with no
// hci_conn_get()/hci_conn_put() pair bracketing its lifetime — a concurrent
// disconnect can free the connection object while the deferred callback is
// still using it (CWE-416 use-after-free).
//
// Detects: wrapper->conn = conn; ... hci_cmd_sync_queue(..., wrapper, ...)
// with no hci_conn_get(conn) call in between.
// Exonerates: the same shape where hci_conn_get(conn) appears before the
// queue call (the fix pattern from abort_conn_sync/create_big_sync/
// le_conn_update_sync/the fixed hci_enhanced_setup_sync).
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file bt_deferred_queue_no_ref.cocci --dir <kernel>/net/bluetooth

virtual report

// ---- VULNERABLE: wrapper->conn = conn (or ->hcon) handed to
//      hci_cmd_sync_queue() with no get() in between --------------------
@race exists@
identifier wrapper;
identifier connval;
identifier qfunc;
expression hdev, destroy, E1;
position p;
@@
  wrapper->conn = connval;
  ... when != hci_conn_get(connval)
      when != hci_conn_get(wrapper->conn)
(
  hci_cmd_sync_queue@p(hdev, qfunc, wrapper, destroy);
|
  E1 = hci_cmd_sync_queue@p(hdev, qfunc, wrapper, destroy);
)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:hci_conn*" % (p[0].file, p[0].line)
)

// ---- SAFE: hci_conn_get() taken before the queue call ---------------------
// (documented as the negative pattern; suppressed from report output)
@safe exists@
identifier wrapper;
identifier connval;
identifier qfunc;
expression hdev, destroy, E1;
@@
  hci_conn_get(connval);
  ... when any
  wrapper->conn = connval;
  ... when any
(
  hci_cmd_sync_queue(hdev, qfunc, wrapper, destroy);
|
  E1 = hci_cmd_sync_queue(hdev, qfunc, wrapper, destroy);
)
