/* +---------------------------------------------------+
 *  ----------- Contract Tests configuration ------------
 *  +---------------------------------------------------+
 */

import org.identityconnectors.common.security.GuardedString


configuration{
    ssl = false
    principal="__configureme__"
    remoteUser="__configureme__"
    password=new GuardedString("__configureme__".toCharArray())
}

environments {
    CaseSuccess{
        configuration {
            ssl = true
        }
    }
    CaseOther {
        configuration {
            remoteUser="FakeAdmin"
        }
    }
}
