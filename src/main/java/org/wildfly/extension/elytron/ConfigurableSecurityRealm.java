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

import java.util.Map;

import org.wildfly.security.auth.spi.SecurityRealm;

/**
 * An extension to the {@link SecurityRealm} API that allows for generic configuration when used within the Elytron subsystem.
 *
 * Ideally {@link SecurityRealm} implementations will be provided by other subsystems that also have their own configuration
 * model, this approach should only be used for truly independent realm implementations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface ConfigurableSecurityRealm extends SecurityRealm {

    /**
     * Initialize the {@link SecurityRealm} with the specified options.
     *
     * @param configuration
     */
    void initialize(final Map<String, String> configuration);

}
