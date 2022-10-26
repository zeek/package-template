# @TEST-EXEC: zeek -Cr ${TRACES}/http-post.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff @ANALYZER_LOWER@.log
#
# @TEST-DOC: Test Zeek parsing a trace file through the @ANALYZER@ analyzer.

# TODO: Adapt as suitable. The example only checks the output of the event
# handler.

event @ANALYZER@::content(f: fa_file, content: string)
    {
    print fmt("Testing @ANALYZER@: %s %s", f$id, content);
    }

