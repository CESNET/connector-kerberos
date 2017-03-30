# Kerberos Connector

Native Kerberos connector based on JNI and MIT libkadm5 library.

The code is partially covered by unit-test.

## Requirements

1. MIT Kerberos Admin library

 * libkadm5 >= 1.15 (for thread safetry)

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
* **attributes** (int)
* **policy** (string)
* (DISABLE\_DATE operational)
* (ENABLE operational)
* (PASSWORD operational)
* **passwordExpirationDate** (PASSWORD\_EXPIRATION\_DATE operational)
* **passwordChangeDate**
* **modifyPrincipal**
* **modifyDate**

## Capabilities

### Supported

#### Create

#### Delete

#### Read

#### Update

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
