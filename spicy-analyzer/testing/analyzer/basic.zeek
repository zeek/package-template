# @TEST-EXEC: zeek -r ${TRACES}/http.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Test @name@ against Zeek with a small trace.

# TODO: As written, this test assumes that the analyzer's Zeek integration adds
# information to conn.
