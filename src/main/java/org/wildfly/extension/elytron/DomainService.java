/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.login.SecurityDomain;
import org.wildfly.security.auth.login.SecurityDomain.RealmBuilder;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.auth.util.RealmMapper;


/**
 * A {@link Service} responsible for managing the lifecycle of a single {@link SecurityDomain}.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainService implements Service<SecurityDomain> {

    private volatile SecurityDomain securityDomain;

    private final String name;
    private final String defaultRealm;
    private final String preRealmNameRewriter;
    private final String postRealmNameRewriter;
    private final Map<String, InjectedValue<NameRewriter>> nameRewriters = new HashMap<>();
    private final Map<String, InjectedValue<SecurityRealm>> realms = new HashMap<>();
    private final Map<String, String> realmRewriterMap = new HashMap<String, String>();
    private final InjectedValue<RealmMapper> realmMapperInjector = new InjectedValue<RealmMapper>();

    DomainService(final String name, final String defaultRealm, final String preRealmNameRewriter, final String postRealmNameRewriter) {
        this.name = name;
        this.defaultRealm = defaultRealm;
        this.preRealmNameRewriter = preRealmNameRewriter;
        this.postRealmNameRewriter = postRealmNameRewriter;
    }

    Injector<NameRewriter> createNameRewriterInjector(final String nameRewriterName) {
        if (nameRewriters.containsKey(nameRewriterName)) {
            return null; // i.e. should already be injected for this name.
        }

        InjectedValue<NameRewriter> nameRewriterInjector = new InjectedValue<>();
        nameRewriters.put(nameRewriterName, nameRewriterInjector);
        return nameRewriterInjector;
    }

    Injector<SecurityRealm> createRealmInjector(final String realmName) throws OperationFailedException {
        if (realms.containsKey(realmName)) {
            throw ROOT_LOGGER.duplicateRealmInjection(name, realmName);
        }

        InjectedValue<SecurityRealm> injector = new InjectedValue<SecurityRealm>();
        realms.put(realmName, injector);
        return injector;
    }

    void associateRealmWithNameRewriter(final String realmName, final String nameRewriterName) {
        realmRewriterMap.put(realmName, nameRewriterName);
    }

    Injector<RealmMapper> getRealmMapperInjector() {
        return realmMapperInjector;
    }

    @Override
    public void start(StartContext context) throws StartException {
        SecurityDomain.Builder builder = SecurityDomain.builder();

        if (preRealmNameRewriter != null) {
            builder.setPreRealmRewriter(nameRewriters.get(preRealmNameRewriter).getValue());
        }
        if (postRealmNameRewriter != null) {
            builder.setPostRealmRewriter(nameRewriters.get(postRealmNameRewriter).getValue());
        }

        RealmMapper realmMapper = realmMapperInjector.getOptionalValue();
        if (realmMapper != null) {
            builder.setRealmMapper(realmMapper);
        }

        builder.setDefaultRealmName(defaultRealm);
        for (Entry<String, InjectedValue<SecurityRealm>> entry : realms.entrySet()) {
            String realmName = entry.getKey();
            RealmBuilder realmBuilder = builder.addRealm(realmName, entry.getValue().getValue());
            if (realmRewriterMap.containsKey(realmName)) {
                realmBuilder.setNameRewriter(nameRewriters.get(realmRewriterMap.get(realmName)).getValue());
            }
        }

        securityDomain = builder.build();
    }

    @Override
    public void stop(StopContext context) {
       securityDomain = null;
    }

    @Override
    public SecurityDomain getValue() throws IllegalStateException, IllegalArgumentException {
        return securityDomain;
    }
}
