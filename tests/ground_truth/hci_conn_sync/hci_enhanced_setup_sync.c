/*
 * Ground-truth fixture: bt_deferred_queue_no_ref shape (no CVE assigned at
 * time of writing). Reduced from the real upstream bug in
 * net/bluetooth/hci_conn.c's hci_enhanced_setup_sync() -- see
 * rules/coccinelle/bt_deferred_queue_no_ref.cocci for the exact commit
 * reference. Not a working exploit.
 */
#include <linux/kernel.h>

struct hci_dev;
struct hci_conn;

struct hci_conn_sync_wrapper {
	struct hci_conn *conn;
};

static int setup_sync_complete(struct hci_dev *hdev, void *data, int err);

static int sample_setup_sync(struct hci_dev *hdev, struct hci_conn *conn)
{
	struct hci_conn_sync_wrapper *wrapper;

	wrapper = kzalloc(sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper)
		return -ENOMEM;

#ifndef FIXED
	/* VULNERABLE: no hci_conn_get() -- a concurrent disconnect can free
	 * conn while the deferred hci_cmd_sync_queue() callback below is
	 * still using it (CWE-416). */
	wrapper->conn = conn;
	hci_cmd_sync_queue(hdev, setup_sync_complete, wrapper, kfree);
	return 0;
#else
	/* FIXED: pin the connection's refcount across the deferred call. */
	wrapper->conn = conn;
	hci_conn_get(conn);
	hci_cmd_sync_queue(hdev, setup_sync_complete, wrapper, kfree);
	return 0;
#endif
}
