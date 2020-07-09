[![Build Status](https://travis-ci.org/CESNET/kerberos-connector.svg?branch=master)](https://travis-ci.org/CESNET/kerberos-connector)
[![Coverage Status](https://coveralls.io/repos/github/CESNET/kerberos-connector/badge.svg?branch=master)](https://coveralls.io/github/CESNET/kerberos-connector?branch=master)


# Kerberos Connector

Native Kerberos [Polygon+ConnId](https://wiki.evolveum.com/display/midPoint/Identity+Connectors) connector based on JNI and MIT libkadm5 library.

Tested with [midPoint](https://evolveum.com/) version 3.5, 3.5.1.

Sample configuration: [samples/kerberos.xml](samples/kerberos.xml).

## Status

All basic functionality is there.

The JNI technology may be risky - it can crash the whole JVM with all applications running. But the code is well covered by unit-tests.

## Requirements

1. MIT Kerberos Admin library

 * libkadm5

2. ConnId (specific version as needed)

## Build

Unit-tests are launched using locally compiled JNI library and fake libkrb5+libkadm5 library.

    mvn clean install

### Build JNI library

JNI library needs to be compiled for the used runtime environment (the midPoint server).

Steps:

    mkdir target
    cd target
    cmake -DTEST=On -DCMAKE_BUILD_TYPE=Debug ../jni
	make

...and then move *libkerberos-connector.so* to the path, where *java.library.path* points.

The native library (non-JNI part) can be checked using provided test example *krbconn\_test*.

## Attributes

Operational attributes:

* **name** (NAME): principal name with the realm suffix
* **UID** (UID, read-only): the same as **name**
* **administrativeStatus** (ENABLE): true if enabled, mapped also to **attributes** and **allowTix**
* **validTo** (DISABLE\_DATE)
* **password** (PASSWORD)
* **passwordExpirationDate** (PASSWORD\_EXPIRATION\_DATE)

Attributes:

* **passwordChangeDate** (long)
* **lastLoginDate** (long)
* **lastFailedDate** (long)
* **attributes** (int): all Kerberos principal flags as integer mask
* **policy** (string)
* **modifyPrincipal** (string)
* **modifyDate** (long)
* **maxTicketLife** (long)
* **maxRenewableLife** (long)
* **allowTix** (boolean): Kerberos principal flag, mapped also to **attributes** and administrative status
* **allowForwardable** (boolean): Kerberos principal flag, mapped also to **attributes**
* **allowRenewable** (boolean): Kerberos principal flag, mapped also to **attributes**
* **requiresPreauth** (boolean): Kerberos principal flag, mapped also to **attributes**
* **requiresHwauth** (boolean): Kerberos principal flag, mapped also to **attributes**
* **requiresPwchange** (boolean): Kerberos principal flag, mapped also to **attributes**

## Capabilities

### Supported

#### Create

See [Update](#update).

#### Delete

#### Read

#### Update

Update is translated to the proper rename, change password, or modify Kadm5 library calls on the Kerberos principal.

**Name**: the account id is the principal name with the realm suffix. Connector will understand the plain name without the realm too, but beware such principal is in the default realm, not the realm configured in the connector. Best practice is always using the realm suffix.

**Kerberos principal flags**: they are represented in schema using particular flag attributes and also by integer mask *attributes*. Also enable/disable is represented by *allowTix* flag. If any combination of values is used during modification:

* particular flag attributes has precedence over *attributes*
* enable/disable state has precedence over *allowTix*

#### Paged Search

All principals matching query are listed, and then fetched one by one for the selected subset.

#### Test

Test will perform new login with configured credentials.

### Not supported

#### Auxiliary object classes

#### Live sync

## Troubleshooing

### PermissionDeniedException with "Kerberos error NUMBER: (no details)" message

Due to limitation of MIT Kadm5 library, it is harder to get user-friendly error messages during initial admin login into Kerberos. Typical exception may look like this:

<tt>org.identityconnectors.framework.common.exceptions.PermissionDeniedException(Kerberos error -1765328203: (no details))</tt>

There are error codes in headers from MIT Kerberos 5:

* */usr/include/krb5.h*
* */usr/include/kadm5/kadm5\_err.h*

You may need to check Kerberos connector configuration parameters, keytab file owner/permissions, *krb5.conf* file, or time.

### Debugging

Debug logs can be enabled:

* Java part: add logger *cz.zcu.KerberosConnector* at midPoint configuration logging page
* JNI part: *debug* configuration option, which will enable logging into syslog

## Developer's Corner

### Get line from crash address

    addr2line -e target/libkerberos-connector.so $ADDRESS
    #or: addr2line -e target/libkadm5_fake.so $ADDRESS

...where *$ADDRESS* is the offset written by JVM for the problematic frame. Debug symbols required.

### Enable core dumps

    echo 'core' > /proc/sys/kernel/core_pattern
	ulimit -c unlimited

### Build without tests

    mvn clean install -DskipTests=true

### Launch specific test

    mvn surefire:test -DargLine= -Dtest=cz.zcu.KerberosConnectorTests#createTest

### Fake Kadm5 library

Mock implementation of the Krb5 and Kadm5 libraries with function used by the JNI part. Data are dynamic, kept in the memory, and initial principals are read from the csv file.

Used config environment variables:

* *FAKE\_KADM5\_DATA*: data file with read-only initial data (default: *target/test-classes/data.csv*)
* *FAKE\_KADM5\_REALM*: emulated realm (default: *EXAMPLE.COM*)

The library is preloaded for unit-tests using *LD\_PRELOAD*.
