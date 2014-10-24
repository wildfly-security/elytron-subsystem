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

package org.wildfly.extension.elytron._private;

import static org.jboss.logging.Logger.Level.INFO;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Messages for the Elytron subsystem.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "WFLYELY", length = 5)
public interface ElytronSubsystemMessages extends BasicLogger {

    /**
     * A root logger with the category of the package name.
     */
    ElytronSubsystemMessages ROOT_LOGGER = Logger.getMessageLogger(ElytronSubsystemMessages.class, "org.wildfly.extension.elytron");

    @LogMessage(level = INFO)
    @Message(id = 1, value = "I am Elytron, nice to meet you.")
    void iAmElytron();

    /**
     * {@link OperationFailedException} if the same realm is injected multiple times for a single domain.
     *
     * @param realmName - the name of the {@link SecurityRealm} being injected.
     * @param domainName - the name of the {@link SecurityDomain} the realm is being injected for.
     * @return The {@link OperationFailedException} for the error.
     */
    @Message(id = 2, value = "Can not inject the same realm '%s' in a single security domain '%s'.")
    OperationFailedException duplicateRealmInjection(final String realmName, final String domainName);

    /**
     * An {@link IllegalArgumentException} if the supplied operation did not contain an address with a value for the required key.
     *
     * @param key - the required key in the address of the operation.
     * @return The {@link IllegalArgumentException} for the error.
     */
    @Message(id = 3, value = "The operation did not contain an address with a value for '%s'.")
    IllegalArgumentException operationAddressMissingKey(final String key);

}
