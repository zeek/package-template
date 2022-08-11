# @TEST-EXEC: zeek -Cr ${TRACES}/raw-layer.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test Zeek parsing a trace file through the @ANALYZER@ analyzer.

# TODO: Adapt as suitable. The example only checks the output of the event
# handler.

event @ANALYZER@::packet(p: raw_pkt_hdr, payload: string)
    {
    print fmt("Testing @ANALYZER@: [%s -> %s] %s", p$l2$src, p$l2$dst, payload);
    }
