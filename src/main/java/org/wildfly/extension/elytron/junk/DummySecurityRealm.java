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

package org.wildfly.extension.elytron.junk;

import java.security.Principal;

import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.provider.RealmIdentity;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.auth.verifier.Verifier;

/**
 * A dummy {@link SecurityRealm} implementation that doesn't do anything.
 *
 * Just gives us something we can inject.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DummySecurityRealm implements SecurityRealm {

    private static final RealmIdentity IDENTITY_INSTANCE = new DummyRealmIdentity();

    @Override
    public RealmIdentity createRealmIdentity(String name) {
        return IDENTITY_INSTANCE;
    }

    @Override
    public RealmIdentity createRealmIdentity(Principal principal) {
        return IDENTITY_INSTANCE;
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) {
        return CredentialSupport.UNSUPPORTED;
    }

    private static final class DummyRealmIdentity implements RealmIdentity {

        @Override
        public String getRealmName() {
            return null;
        }

        @Override
        public Principal getPrincipal() {
            return null;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) {
            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <P> P proveAuthentic(Verifier<P> verifier) throws AuthenticationException {
            return null;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) {
            return null;
        }

        @Override
        public SecurityIdentity createSecurityIdentity() {
            return null;
        }

    }

}
