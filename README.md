# Kerberos Connector

Native Kerberos [Polygon+ConnId](https://wiki.evolveum.com/display/midPoint/Identity+Connectors) connector based on JNI and MIT libkadm5 library.

Tested with [midPoint](https://evolveum.com/) version 3.5.

## Status

Basic functionality is there. Several important features are missing. Also as typical for JNI technology and heavy development, it may crash all applications running, or eat your home pets.

The code is partially covered by unit-tests.

## Requirements

1. MIT Kerberos Admin library

 * libkadm5 >= 1.15 (for thread safety)

2. ConnId (specific version as needed)

 * connector-parent (com.evolveum.polygon)
 * connector-framework (net.tirasa.connid)

## Build

Unit-tests are launched using locally compiled JNI library and fake libkrb5+libkadm5 library.

    mvn clean install

### Build JNI library

JNI library needs to be compiled for the used runtime environment.

Steps:

    mkdir target
    cd target
    cmake -DTEST=On -DCMAKE_BUILD_TYPE=Debug ../jni
	make

...and then move *libkerberos-connector.so* to the path, where *java.library.path* points.

The native library (non-JNI part) can be checked using provided test example *krbconn\_test*.

## Attributes

* **name** (string): principal name (without the realm suffix)
* **UID** (string, read-only): the same as **name**
* **attributes** (int): all Kerberos principal flags as integer mask
* **policy** (string)
* administrative status (ENABLE operational): true if enabled, mapped also to **attributes** and **allowTix**
* (DISABLE\_DATE operational)
* (PASSWORD operational)
* **passwordExpirationDate** (PASSWORD\_EXPIRATION\_DATE operational)
* **passwordChangeDate**
* **modifyPrincipal**
* **modifyDate**
* **allowTix**: Kerberos principal flag, mapped also to **attributes** and administrative status
* **allowForwardable**: Kerberos principal flag, mapped also to **attributes**
* **allowRenewable**: Kerberos principal flag, mapped also to **attributes**
* **requiresPreauth**: Kerberos principal flag, mapped also to **attributes**
* **requiresHwauth**: Kerberos principal flag, mapped also to **attributes**
* **requiresPwchange**: Kerberos principal flag, mapped also to **attributes**

## Capabilities

### Supported

#### Create

#### Delete

#### Read

#### Update

Update is translated to the proper rename, change password, or modify Kadm5 library calls on the Kerberos principal.

Note, the Kerberos principal flags are represented in schema using particular flag attributes and also by integer mask *attributes*. Also enable/disable is represented by *allowTix*. If any combination of values is used during modification:

* particular flag attributes has precedence before *attributes*
* enable/disable state has precedence before *allowTix*

#### Paged Search

All principals matching query are listed, and then fetched one by one for the selected subset.

#### Test

Test will perform new login with configured credentials.

### Not supported

#### Auxiliary object classes

#### Live sync

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

    mvn surefire:test -Dtest=cz.zcu.KerberosConnectorTests#createTest
