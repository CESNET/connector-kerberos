#! /bin/sh -e

#
# Script to cleanup KDC after testing
#
# Intended for integration testing using real KDC server.
#
# MIT Kadm5 library > 1.12 required.
#

export KRB5_CONFIG

IFS=','
cat `dirname $0`/data.csv | tail -n +2 | while read name pass policy flags modprinc moddate; do
	echo $name $policy;

	kadmin.local -r EXAMPLE.COM delprinc "${name}@EXAMPLE.COM" || :
done
for p in Foo host/foo rename-test2; do
	kadmin.local -r EXAMPLE.COM delprinc "${p}@EXAMPLE.COM" || :
done
