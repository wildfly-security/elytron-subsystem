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

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.wildfly.security.auth.spi.SecurityRealm;


/**
 * A simple {@link Service} that produces a {@link DummySecurityRealm}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DummyRealmService implements Service<SecurityRealm> {

    private volatile SecurityRealm securityRealm;

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

    @Override
    public void start(StartContext arg0) throws StartException {
        securityRealm = new DummySecurityRealm();
    }

    @Override
    public void stop(StopContext arg0) {
        securityRealm = null;
    }

}
