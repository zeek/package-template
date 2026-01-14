# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER='zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p proto service' btest-diff conn.log

event zeek_done()
	{
	print "Goodbye world!";
	}
