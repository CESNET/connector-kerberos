/* +---------------------------------------------------+
 *  ----------- Contract Tests configuration ------------
 *  +---------------------------------------------------+
 */

import org.identityconnectors.common.security.GuardedString


configuration{
    // see jni/kadm5_fake.c
    principal="admin@EXAMPLE.COM"
    password=new GuardedString("password".toCharArray())
}

environments {
    CaseSuccess{
        configuration {
        }
    }
    CaseOther {
        configuration {
            remoteUser="FakeAdmin"
        }
    }
}
