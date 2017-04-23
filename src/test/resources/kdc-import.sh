#! /bin/sh -e

#
# Script to import test data into KDC
#
# Intended for integration testing using real KDC server.
#
# MIT Kadm5 library > 1.12 required.
#

export KRB5_CONFIG

IFS=','
cat `dirname $0`/data.csv | tail -n +2 | while read name pass policy flags modprinc moddate; do
	echo $name $policy;

	args=''
	if [ -n "$policy" ]; then args="$args -policy '$policy'"; fi
	if [ -n "$pass" ]; then
		args="$args -pw '$pass'"
	else
		args="$args -randkey"
	fi

	kargs='-r EXAMPLE.COM'
	if [ -n "$modprinc" ]; then kargs="$kargs -p '$modprinc'"; fi
	eval kadmin.local "$kargs" ank "$args" "${name}@EXAMPLE.COM"
done
