/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron;

import java.security.KeyStore;
import java.security.Provider;

import org.jboss.as.controller.capability.RuntimeCapability;
import org.wildfly.security.auth.login.SecurityDomain;
import org.wildfly.security.auth.spi.SecurityRealm;


/**
 * The capabilities provided by and required by this subsystem.
 *
 * It is a deliberate decision that this class is not public, by using capability definitions it should be possible to
 * completely remove this subsystem and allow another to provide all the capabilities - allowing references to this class would
 * not allow complete removal.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class Capabilities {

    private static final String CAPABILITY_BASE = "org.wildfly.security.";

    static final String KEYSTORE_CAPABILITY = CAPABILITY_BASE + "keystore";

    static final RuntimeCapability<Void> KEY_STORE_RUNTIME_CAPABILITY =  RuntimeCapability
        .Builder.of(KEYSTORE_CAPABILITY, true, KeyStore.class)
        .build();

    static final String PROVIDERS_CAPABILITY = CAPABILITY_BASE + "providers";

    static final RuntimeCapability<Void> PROVIDERS_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PROVIDERS_CAPABILITY, true, Provider[].class)
            .build();

    static final String SECURITY_DOMAIN_CAPABILITY = CAPABILITY_BASE + "security-domain";

    static final RuntimeCapability<Void> SECURITY_DOMAIN_RUNTIME_CAPABILITY = RuntimeCapability
        .Builder.of(SECURITY_DOMAIN_CAPABILITY, true, SecurityDomain.class)
        .build();

    static final String SECURITY_REALM_CAPABILITY = CAPABILITY_BASE + "security-realm";

    static final RuntimeCapability<Void> SECURITY_REALM_RUNTIME_CAPABILITY = RuntimeCapability
        .Builder.of(SECURITY_REALM_CAPABILITY, true, SecurityRealm.class)
        .build();

}
