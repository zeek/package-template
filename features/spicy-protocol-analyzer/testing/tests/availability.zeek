# @TEST-DOC: Check that the @ANALYZER@ analyzer is available.
#
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_SPICY__?@ANALYZER_UPPER@'
