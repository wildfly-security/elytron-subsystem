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

import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_SASL_CONFIGURATION_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.SaslFactoryRuntimeResource.wrap;

import javax.security.sasl.SaslServerFactory;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityDomainSaslConfiguration;

/**
 * A {@link ResourceDefinition} for a {@link SecurityDomainSaslConfiguration} which is a pairing of a {@link SecurityDomain} and
 * a {@link SaslServerFactory}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SecurityDomainSaslConfigurationDefinition extends SimpleResourceDefinition {

    static final SimpleAttributeDefinition SECURITY_DOMAIN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SECURITY_DOMAIN_SASL_CONFIGURATION_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition SASL_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SASL_SERVER_FACTORY, ModelType.STRING, false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(SASL_SERVER_FACTORY_CAPABILITY, SECURITY_DOMAIN_SASL_CONFIGURATION_CAPABILITY, true)
        .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { SECURITY_DOMAIN, SASL_SERVER_FACTORY };

    private static final AbstractAddStepHandler ADD = new AddHandler();
    private static final OperationStepHandler REMOVE = new RemoveHandler(ADD);

    private SecurityDomainSaslConfigurationDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.SECURITY_DOMAIN_SASL_CONFIGURATION),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.SECURITY_DOMAIN_SASL_CONFIGURATION))
        .setAddHandler(ADD)
        .setRemoveHandler(REMOVE)
        .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
        .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
    }

    static ResourceDefinition create() {
        return wrap(new SecurityDomainSaslConfigurationDefinition(), SecurityDomainSaslConfigurationDefinition::getSaslServerFactory);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        WriteAttributeHandler write = new WriteAttributeHandler();
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, write);
        }
    }

    private static SaslServerFactory getSaslServerFactory(OperationContext context) throws OperationFailedException {
        RuntimeCapability<Void> runtimeCapability = SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
        ServiceName securityDomainSaslConfigurationName = runtimeCapability.getCapabilityServiceName(SecurityDomainSaslConfiguration.class);

        @SuppressWarnings("unchecked")
        ServiceController<SecurityDomainSaslConfiguration> serviceContainer = (ServiceController<SecurityDomainSaslConfiguration>) context.getServiceRegistry(false).getRequiredService(securityDomainSaslConfigurationName);
        if (serviceContainer.getState() != State.UP) {
            return null;
        }
        return serviceContainer.getValue().getSaslServerFactory();
    }

    private static class AddHandler extends AbstractAddStepHandler {

        private AddHandler() {
            super(SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName serviceName = runtimeCapability.getCapabilityServiceName(SecurityDomainSaslConfiguration.class);

            String securityDomain = SECURITY_DOMAIN.resolveModelAttribute(context, model).asString();
            String saslServerFactory = SASL_SERVER_FACTORY.resolveModelAttribute(context, model).asString();

            final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
            final InjectedValue<SaslServerFactory> saslServerFactoryInjector = new InjectedValue<SaslServerFactory>();

            TrivialService<SecurityDomainSaslConfiguration> serviceInstance = new TrivialService<SecurityDomainSaslConfiguration>(
                    () -> new SecurityDomainSaslConfiguration(securityDomainInjector.getValue(), saslServerFactoryInjector.getValue()));

            ServiceBuilder<SecurityDomainSaslConfiguration> serviceBuilder = serviceTarget.addService(serviceName, serviceInstance);

            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    RuntimeCapability.buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain),
                    SecurityDomain.class), SecurityDomain.class, securityDomainInjector);

            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    RuntimeCapability.buildDynamicCapabilityName(SASL_SERVER_FACTORY_CAPABILITY, saslServerFactory),
                    SaslServerFactory.class), SaslServerFactory.class, saslServerFactoryInjector);

            commonDependencies(serviceBuilder)
                .setInitialMode(Mode.LAZY)
                .install();
        }
    }

    private static class RemoveHandler extends ServiceRemoveStepHandler {

        public RemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY.fromBaseCapability(name).getCapabilityServiceName(SecurityDomainSaslConfiguration.class);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.SECURITY_DOMAIN_SASL_CONFIGURATION, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return SECURITY_DOMAIN_SASL_CONFIGURATION_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(SecurityDomainSaslConfiguration.class);
        }
    }
}
