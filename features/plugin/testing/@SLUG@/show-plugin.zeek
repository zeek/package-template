# @TEST-EXEC: zeek -NN @NS@::@NAME@ |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
