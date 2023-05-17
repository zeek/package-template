# @TEST-DOC: Check that the @ANALYZER@ analyzer is available.
#
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_@ANALYZER_UPPER@'
