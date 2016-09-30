elytron-subsystem
=================

Subsystem to enable configuration of Elytron within WildFly

Installation into wildfly-core
------------------------------

Subsystem currently require [patched version of wildfly-core](https://github.com/wildfly-security-incubator/wildfly-core/tree/remoting5_integration) from incubator (branch *remoting5_integration*), which require [patched version of undertow](https://github.com/wildfly-security-incubator/undertow/tree/elytron_integration) (branch *elytron_integration*).

After their compilation using `mvn install` it is possible to install this subsystem into compiled wildfly-core:

```
mvn clean install -Pinstall2wildfly-core -Dwildfly.core.home=/my/path/wildfly-core/dist/target/wildfly-core-3.0.0.Alpha8-SNAPSHOT
```

Then you can start wildfly-core using its `standalone.sh`. Extension and blank subsystem `/subsystem=elytron` will be already added.

**Note:**
-----
When adding new capabilities add them to [Capabilities And Requirements document](https://developer.jboss.org/wiki/WildFlySecurityElytron-CapabilitiesAndRequirements-Reference), please.
