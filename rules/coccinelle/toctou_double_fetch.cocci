// racemap: a shared/DMA-visible struct field is read once for a bounds/
// validity check, then read AGAIN (same base expression, same field) for
// actual use, without ever being snapshotted into a local via READ_ONCE()/a
// plain assignment. If the backing memory is attacker/device/hypervisor-
// writable (DMA-coherent buffers, MMIO, shared pages under SEV-SNP/TDX,
// etc.), the value can change between the check and the use, bypassing the
// validation entirely — CWE-367 TOCTOU, specifically the "double-fetch"
// variant.
//
// Ground-truth case: CVE-2026-64034, "net: mana: Fix TOCTOU double-fetch of
// hwc_msg_id from DMA buffer" (drivers/net/ethernet/microsoft/mana/hw_channel.c) —
// resp->response.hwc_msg_id bounds-checked once, then re-read from the same
// DMA-coherent buffer for test_bit()/pointer arithmetic; a hostile hypervisor
// can flip the value in between on a Confidential VM, bypassing the check
// (CVSS 9.3 CRITICAL). Fixed by reading once via READ_ONCE() into a local and
// passing that validated value everywhere instead of re-reading the field.
//
// Scope note: this rule only catches the *same-function* form of the bug
// (check and reuse in one function body) — the real CVE-2026-64034 instance
// split the check and the reuse across two functions
// (mana_hwc_rx_event_handler() checks, mana_hwc_handle_resp() re-reads), which
// needs interprocedural reasoning this rule doesn't attempt. Still useful:
// it catches the more common single-function shape of this bug class, and a
// human/LLM triage pass can widen the check manually for a specific
// candidate that looks like it might split across a helper call.
//
// Exonerates: the field is captured into a local via READ_ONCE() (or a
// plain assignment) immediately after (or as part of) the check, and only
// the local is used afterward.
//
// (Metavariable named `fld`, not `field`: like the sibling
// shared_iv_no_snapshot.cocci's note about `iv`, naming the metavariable
// after the exact word appearing in `X->field` syntax confuses this
// Coccinelle build's parser.)
//
// Output convention: each match prints  // RACEMAP:<file>:<line>:<field>
//
// Run:  spatch --sp-file toctou_double_fetch.cocci -D report --dir <kernel>/drivers

virtual report

@race exists@
expression SF;
expression N;
expression E1;
position p;
@@
  if (SF >= N)
  {
    ...
    return ...;
  }
  ... when != SF = ...
      when != READ_ONCE(SF)
  E1@p(..., SF, ...)

@script:python depends on race && report@
p << race.p;
@@
coccilib.report.print_report(
    p[0],
    "RACEMAP:%s:%s:double-fetch" % (p[0].file, p[0].line)
)

@safe exists@
expression SF;
expression local;
expression E1;
@@
  local = READ_ONCE(SF);
  ... when any
  E1(..., local, ...)
