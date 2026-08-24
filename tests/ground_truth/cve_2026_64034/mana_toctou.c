/*
 * Ground-truth fixture: CVE-2026-64034, "net: mana: Fix TOCTOU double-fetch
 * of hwc_msg_id from DMA buffer" (CVSS 9.3 CRITICAL).
 *
 * Root cause: resp->response.hwc_msg_id was read once from DMA-coherent
 * memory (mapped uncacheable on x86, shared/unencrypted in Confidential
 * VMs) and bounds-checked, then re-read from the same buffer for
 * test_bit()/pointer arithmetic -- a hostile hypervisor could flip the
 * value in between, bypassing the bounds validation entirely. The fix reads
 * the field exactly once via READ_ONCE() into a stack-local and uses only
 * that validated value afterward.
 *
 * racemap must flag the vulnerable variant as likely_race and exonerate the
 * snapshotted variant. Synthetic test input -- not a working exploit.
 */
#include <linux/types.h>

struct gdma_resp_hdr {
	struct {
		u16 hwc_msg_id;
	} response;
};

struct hw_channel_context {
	int dev;
};

static void handle_resp(struct hw_channel_context *hwc, u16 msg_id);

static void hwc_rx_event_handler(struct hw_channel_context *hwc,
				 struct gdma_resp_hdr *resp,
				 u32 num_inflight_msg)
{
#ifndef FIXED
	/* VULNERABLE: checked once here... */
	if (resp->response.hwc_msg_id >= num_inflight_msg) {
		return;
	}

	/* ...but re-read from the same shared buffer here, no snapshot. */
	handle_resp(hwc, resp->response.hwc_msg_id);
#else
	u16 msg_id;

	/* FIXED: read exactly once, snapshot into a local. */
	msg_id = READ_ONCE(resp->response.hwc_msg_id);
	if (msg_id >= num_inflight_msg) {
		return;
	}

	handle_resp(hwc, msg_id);
#endif
}
