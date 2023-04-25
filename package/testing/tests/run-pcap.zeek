# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT >output
#
# Zeek 6 and newer populate the local_orig and local_resp columns by default,
# while earlier ones only do so after manual configuration. Filter out these
# columns to allow robust baseline comparison:
# @TEST-EXEC: cat conn.log | zeek-cut -m -n local_orig local_resp >conn.log.filtered
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff conn.log.filtered

event zeek_done()
	{
	print "Goodbye world!";
	}
