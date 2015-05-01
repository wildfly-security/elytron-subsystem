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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.RealmDefinition.REALM_SERVICE_UTIL;

import java.util.List;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.security.auth.provider.SecurityDomain;
import org.wildfly.security.auth.provider.SecurityRealm;

/**
 * A {@link ResourceDefinition} for a single domain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainDefinition extends SimpleResourceDefinition {

    private static final ServiceUtil<SecurityDomain> DOMAIN_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_DOMAIN_RUNTIME_CAPABILITY, ElytronDescriptionConstants.DOMAIN, SecurityDomain.class);

    static final SimpleAttributeDefinition DEFAULT_REALM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DEFAULT_REALM, ModelType.STRING, false)
             .setAllowExpression(false)
             .setMinSize(1)
             .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
             .build();

    static final StringListAttributeDefinition REALMS =  new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.REALMS)
             .setAllowExpression(true)
             .setAllowNull(false)
             .setCapabilityReference(SECURITY_REALM_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
             .build();

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { DEFAULT_REALM, REALMS };

    private static final DomainAddHandler ADD = new DomainAddHandler();
    private static final DomainRemoveHandler REMOVE = new DomainRemoveHandler(ADD);
    private static final WriteAttributeHandler WRITE = new WriteAttributeHandler(ElytronDescriptionConstants.DOMAIN);

    DomainDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.DOMAIN),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.DOMAIN),
                ADD, REMOVE,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES,
                OperationEntry.Flag.RESTART_RESOURCE_SERVICES);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    private static ServiceController<SecurityDomain> installService(OperationContext context, ServiceName domainName, ModelNode model) throws OperationFailedException {
        ServiceTarget serviceTarget = context.getServiceTarget();
        String simpleName = domainName.getSimpleName();

        String defaultRealm = DomainDefinition.DEFAULT_REALM.resolveModelAttribute(context, model).asString();
        List<String> realms = DomainDefinition.REALMS.unwrap(context, model);

        DomainService domain = new DomainService(simpleName, defaultRealm);

        ServiceBuilder<SecurityDomain> domainBuilder = serviceTarget.addService(domainName, domain)
                .setInitialMode(Mode.LAZY);

        for (String current : realms) {
            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(SECURITY_REALM_CAPABILITY, current);
            ServiceName realmServiceName = context.getCapabilityServiceName(runtimeCapability, SecurityRealm.class);

            REALM_SERVICE_UTIL.addInjection(domainBuilder, domain.createRealmInjector(current), realmServiceName);
        }

        commonDependencies(domainBuilder);
        return domainBuilder.install();
    }

    private static class DomainAddHandler extends AbstractAddStepHandler {

        private DomainAddHandler() {
            super(SECURITY_DOMAIN_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            RuntimeCapability<Void> runtimeCapability = RuntimeCapability.fromBaseCapability(SECURITY_DOMAIN_RUNTIME_CAPABILITY, context.getCurrentAddressValue());
            ServiceName domainName = runtimeCapability.getCapabilityServiceName(SecurityDomain.class);

            installService(context, domainName, model);
        }

    }

    private static class DomainRemoveHandler extends ServiceRemoveStepHandler {

        public DomainRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SECURITY_DOMAIN_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return super.serviceName(name);
        }


    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        public WriteAttributeHandler(String parentKeyName) {
            super(parentKeyName, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress parentAddress) {
            // TODO - This does not look correct.
            return DOMAIN_SERVICE_UTIL.serviceName(parentAddress.toModelNode());
        }


        @Override
        protected void recreateParentService(OperationContext context, PathAddress parentAddress, ModelNode parentModel)
                throws OperationFailedException {
            installService(context, getParentServiceName(parentAddress), parentModel);
        }

    }

}
