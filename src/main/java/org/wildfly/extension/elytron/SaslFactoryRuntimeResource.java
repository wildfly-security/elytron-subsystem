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

import java.util.Collections;
import java.util.Map;

import javax.security.sasl.SaslServerFactory;

import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
import org.jboss.as.controller.DelegatingResourceDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.dmr.ModelNode;

/**
 * A {@link ResourceDefintion} to wrap an existing resource and add a runtime attribute to return the available SASL mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SaslFactoryRuntimeResource extends DelegatingResourceDefinition {

    private static final Map<String, ?> EMPTY_MAP = Collections.emptyMap();

    private final FactoryFunction saslServerFactory;

    private static final StringListAttributeDefinition AVAILABLE_MECHANISMS = new StringListAttributeDefinition.Builder(
            ElytronDescriptionConstants.AVAILABLE_MECHANISMS).setStorageRuntime().build();

    private SaslFactoryRuntimeResource(ResourceDefinition delegate, FactoryFunction saslServerFactory) {
        this.saslServerFactory = saslServerFactory;
        setDelegate(delegate);
    }

    static ResourceDefinition wrap(ResourceDefinition delegate, FactoryFunction saslServerFactory) {
        return new SaslFactoryRuntimeResource(delegate, saslServerFactory);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        super.registerAttributes(resourceRegistration);

        resourceRegistration.registerReadOnlyAttribute(AVAILABLE_MECHANISMS, new AvailableMechanismsHandler());
    }

    private class AvailableMechanismsHandler extends AbstractRuntimeOnlyHandler {

        @Override
        protected void executeRuntimeStep(OperationContext context, ModelNode operation) throws OperationFailedException {
            SaslServerFactory saslServerFactory = SaslFactoryRuntimeResource.this.saslServerFactory.get(context);

            if (saslServerFactory != null) {
                String[] mechanisms = saslServerFactory.getMechanismNames(EMPTY_MAP);
                ModelNode mechanismList = new ModelNode();
                for (String current : mechanisms) {
                    mechanismList.add(current);
                }
                context.getResult().set(mechanismList);
            }
        }

    }

    /**
     * A Function that returns a {@link SaslServerFactory} whilst allowing an {@link OperationFailedException} to be thrown if
     * not available.
     */
    @FunctionalInterface
    interface FactoryFunction {

        SaslServerFactory get(OperationContext context) throws OperationFailedException;

    }

}
