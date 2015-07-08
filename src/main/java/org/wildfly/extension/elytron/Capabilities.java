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
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;


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

    static final String NAME_REWRITER_CAPABILITY = CAPABILITY_BASE + "name-rewriter";

    static final RuntimeCapability<Void> NAME_REWRITER_RUNTIME_CAPABILITY =  RuntimeCapability
        .Builder.of(NAME_REWRITER_CAPABILITY, true, NameRewriter.class)
        .build();

    static final String PERMISSION_MAPPER_CAPABILITY = CAPABILITY_BASE + "permission-mapper";

    static final RuntimeCapability<Void> PERMISSION_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(PERMISSION_MAPPER_CAPABILITY, true, PermissionMapper.class)
            .build();

    static final String PRINCIPAL_DECODER_CAPABILITY = CAPABILITY_BASE + "principal-decoder";

    static final RuntimeCapability<Void> PRINCIPAL_DECODER_RUNTIME_CAPABILITY =  RuntimeCapability
        .Builder.of(PRINCIPAL_DECODER_CAPABILITY, true, PrincipalDecoder.class)
        .build();

    static final String PROVIDERS_CAPABILITY = CAPABILITY_BASE + "providers";

    static final RuntimeCapability<Void> PROVIDERS_RUNTIME_CAPABILITY =  RuntimeCapability
        .Builder.of(PROVIDERS_CAPABILITY, true, Provider[].class)
        .build();

    static final String REALM_MAPPER_CAPABILITY = CAPABILITY_BASE + "realm-mapper";

    static final RuntimeCapability<Void> REALM_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(REALM_MAPPER_CAPABILITY, true, RealmMapper.class)
            .build();

    static final String ROLE_DECODER_CAPABILITY = CAPABILITY_BASE + "role-decoder";

    static final RuntimeCapability<Void> ROLE_DECODER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(ROLE_DECODER_CAPABILITY, true, RoleDecoder.class)
            .build();

    static final String ROLE_MAPPER_CAPABILITY = CAPABILITY_BASE + "role-mapper";

    static final RuntimeCapability<Void> ROLE_MAPPER_RUNTIME_CAPABILITY =  RuntimeCapability
            .Builder.of(ROLE_MAPPER_CAPABILITY, true, RoleMapper.class)
            .build();

    static final String SECURITY_DOMAIN_CAPABILITY = CAPABILITY_BASE + "security-domain";

    static final RuntimeCapability<Void> SECURITY_DOMAIN_RUNTIME_CAPABILITY = RuntimeCapability
        .Builder.of(SECURITY_DOMAIN_CAPABILITY, true, SecurityDomain.class)
        .build();

    static final String SECURITY_REALM_CAPABILITY = CAPABILITY_BASE + "security-realm";

    static final RuntimeCapability<Void> SECURITY_REALM_RUNTIME_CAPABILITY = RuntimeCapability
        .Builder.of(SECURITY_REALM_CAPABILITY, true, SecurityRealm.class)
        .build();

    /**
     * Requirements, capabilities from other subsystems.
     */

    /**
     * Required by the {@link JdbcRealmDefinition}.
     */
    static final String DATA_SOURCE_CAPABILITY_NAME = "org.wildfly.data-source";
}
