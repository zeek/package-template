# @TEST-EXEC: zeek -Cr ${TRACES}/raw-layer.pcap ${PACKAGE} %INPUT >output
#
# Filter out columns which are incompatible across supported Zeek versions:
#
# - Zeek 6 and newer populate the local_orig and local_resp columns by default,
#   while earlier ones only do so after manual configuration.
# - Zeek 7.1 adds a column `ip_proto`.
#
# @TEST-EXEC: cat conn.log | zeek-cut -m -n local_orig local_resp ip_proto >conn.log.filtered
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log.filtered
#
# @TEST-DOC: Test Zeek parsing a trace file through the @ANALYZER@ analyzer.

# TODO: Adapt as suitable. The example only checks the output of the event
# handler.

event @ANALYZER@::packet(p: raw_pkt_hdr, payload: string)
    {
    print fmt("Testing @ANALYZER@: [%s -> %s] %s", p$l2$src, p$l2$dst, payload);
    }
