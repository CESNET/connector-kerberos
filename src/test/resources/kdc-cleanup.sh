#! /bin/sh -e

#
# Script to cleanup KDC after testing
#
# Intended for integration testing using real KDC server.
#

export KRB5_CONGIG

IFS=','
cat `dirname $0`/data.csv | tail -n +2 | while read name pass policy flags modprinc moddate; do
	echo $name $policy;

	kadmin.local -r EXAMPLE.COM delprinc "${name}@EXAMPLE.COM" || :
done
for p in Foo host/foo rename-test2; do
	kadmin.local -r EXAMPLE.COM delprinc "${p}@EXAMPLE.COM" || :
done
