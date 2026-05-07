// Spring4Shell shape (CVE-2022-22965, spring-core 5.3.17 and earlier
// on JDK 9+). The vulnerability let an attacker manipulate the
// ClassLoader through Spring's data-binding using a crafted POST,
// chaining through getClass().getProtectionDomain().getCodeSource()
// → write a JSP webshell into Tomcat's webroot.
//
// This minimum-shape fixture reproduces the AST signal aegis sees:
// reflection chain (Class.forName + Method.invoke) + a file-write
// to a path outside the request scope. The actual CVE was about
// the BeanWrapper allowing access to the classLoader; we model the
// downstream RCE primitive.
//
// Detection target:
//   - dynamic-eval (Class.forName + Method.invoke)
//   - net-egress   (URL.openConnection — second-stage fetch)
//   - fs-write-outside-root (FileOutputStream into webroot)

package org.springframework.beans;

import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.net.URL;

public class CachedIntrospectionResults {
    public Object exploit(String className, String webrootPath, String stage2Url) throws Exception {
        URL url = new URL(stage2Url);
        url.openConnection().getInputStream();

        Class<?> cls = Class.forName(className);
        Object instance = cls.getDeclaredConstructor().newInstance();
        Method run = cls.getMethod("run");

        FileOutputStream fos = new FileOutputStream(webrootPath + "/shell.jsp");
        fos.write(("<%= " + run.invoke(instance) + " %>").getBytes());
        fos.close();
        return null;
    }
}
