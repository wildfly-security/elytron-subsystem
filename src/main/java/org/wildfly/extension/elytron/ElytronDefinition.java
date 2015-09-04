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

import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PERMISSION_MAPPER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PRINCIPAL_DECODER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.ROLE_DECODER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.ROLE_MAPPER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import org.jboss.as.controller.AbstractBoottimeAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationContext.AttachmentKey;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;

/**
 * Top level {@link ResourceDefinition} for the Elytron subsystem.
 *
 * @author <a href="mailto:tcerar@redhat.com">Tomaz Cerar</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronDefinition extends SimpleResourceDefinition {

    public static final ElytronDefinition INSTANCE = new ElytronDefinition();

    private static final AttachmentKey<SecurityPropertyService> SECURITY_PROPERTY_SERVICE_KEY = AttachmentKey.create(SecurityPropertyService.class);

    private ElytronDefinition() {
        super(ElytronExtension.SUBSYSTEM_PATH,
                ElytronExtension.getResourceDescriptionResolver(),
                new ElytronAdd(),new ElytronRemove());
    }

    @Override
    public void registerChildren(ManagementResourceRegistration resourceRegistration) {
        // Security Properties
        resourceRegistration.registerSubModel(new SecurityPropertyResourceDefinition());

        // Provider Loader
        resourceRegistration.registerSubModel(new ProviderLoaderDefinition());

        // Security Domain SASL / HTTP Configurations
        resourceRegistration.registerSubModel(SaslServerDefinitions.getSecurityDomainSaslConfiguration());
        resourceRegistration.registerSubModel(HttpServerDefinitions.getSecurityDomainHttpServerConfiguration());

        // Domain
        resourceRegistration.registerSubModel(new DomainDefinition());
        // Security Realms
        resourceRegistration.registerSubModel(new AggregateRealmDefinition());
        resourceRegistration.registerSubModel(SecurityRealmResourceDecorator.wrap(new CustomComponentDefinition<SecurityRealm>(SecurityRealm.class, SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_REALM)));
        resourceRegistration.registerSubModel(new JaasRealmDefinition());
        resourceRegistration.registerSubModel(new JdbcRealmDefinition());
        resourceRegistration.registerSubModel(new KeyStoreRealmDefinition());
        resourceRegistration.registerSubModel(new PropertiesRealmDefinition());
        resourceRegistration.registerSubModel(new LdapRealmDefinition());
        resourceRegistration.registerSubModel(SecurityRealmResourceDecorator.wrap(new FileSystemRealmDefinition()));

        // Name Rewriters
        resourceRegistration.registerSubModel(NameRewriterDefinitions.getAggregateNameRewriterDefinition());
        resourceRegistration.registerSubModel(NameRewriterDefinitions.getChainedNameRewriterDefinition());
        resourceRegistration.registerSubModel(NameRewriterDefinitions.getConstantNameRewriterDefinition());
        resourceRegistration.registerSubModel(new CustomComponentDefinition<NameRewriter>(NameRewriter.class, NAME_REWRITER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_NAME_REWRITER));
        resourceRegistration.registerSubModel(NameRewriterDefinitions.getRegexNameRewriterDefinition());
        resourceRegistration.registerSubModel(NameRewriterDefinitions.getRegexNameValidatingRewriterDefinition());

        // Permission Mapper
        resourceRegistration.registerSubModel(new CustomComponentDefinition<PermissionMapper>(PermissionMapper.class, PERMISSION_MAPPER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_PERMISSION_MAPPER));

        // Principal Decoders
        resourceRegistration.registerSubModel(PrincipalDecoderDefinitions.getAggregatePrincipalDecoderDefinition());
        resourceRegistration.registerSubModel(new CustomComponentDefinition<PrincipalDecoder>(PrincipalDecoder.class, PRINCIPAL_DECODER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_PRINCIPAL_DECODER));
        resourceRegistration.registerSubModel(PrincipalDecoderDefinitions.getX500AttributePrincipalDecoder());

        // Realm Mappers
        resourceRegistration.registerSubModel(new CustomComponentDefinition<RealmMapper>(RealmMapper.class, REALM_MAPPER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_REALM_MAPPER));
        resourceRegistration.registerSubModel(RealmMapperDefinitions.getMappedRegexRealmMapper());
        resourceRegistration.registerSubModel(RealmMapperDefinitions.getSimpleRegexRealmMapperDefinition());

        // Role Decoders
        resourceRegistration.registerSubModel(new CustomComponentDefinition<RoleDecoder>(RoleDecoder.class, ROLE_DECODER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_ROLE_DECODER));
        resourceRegistration.registerSubModel(RoleDecoderDefinitions.getEmptyRoleDecoderDefinition());
        resourceRegistration.registerSubModel(RoleDecoderDefinitions.getSimpleRoleDecoderDefinition());

        // Role Mappers
        resourceRegistration.registerSubModel(RoleMapperDefinitions.getAddSuffixRoleMapperDefinition());
        resourceRegistration.registerSubModel(RoleMapperDefinitions.getAddPrefixRoleMapperDefinition());
        resourceRegistration.registerSubModel(RoleMapperDefinitions.getAggregateRoleMapperDefinition());
        resourceRegistration.registerSubModel(RoleMapperDefinitions.getConstantRoleMapperDefinition());
        resourceRegistration.registerSubModel(new CustomComponentDefinition<RoleMapper>(RoleMapper.class, ROLE_MAPPER_RUNTIME_CAPABILITY, ElytronDescriptionConstants.CUSTOM_ROLE_MAPPER));
        resourceRegistration.registerSubModel(RoleMapperDefinitions.getLogicalRoleMapperDefinition());

        // HTTP Mechanisms
        resourceRegistration.registerSubModel(HttpServerDefinitions.getAggregateHttpServerFactoryDefintion());
        resourceRegistration.registerSubModel(HttpServerDefinitions.getConfigurableHttpServerFactoryDefinition());
        resourceRegistration.registerSubModel(HttpServerDefinitions.getProviderHttpServerFactoryDefinition());
        resourceRegistration.registerSubModel(HttpServerDefinitions.getServiceLoaderServerFactoryDefinition());

        // SASL Mechanisms
        resourceRegistration.registerSubModel(SaslServerDefinitions.getAggregateSaslServerFactoryDefinition());
        resourceRegistration.registerSubModel(SaslServerDefinitions.getConfigurableSaslServerFactoryDefinition());
        resourceRegistration.registerSubModel(SaslServerDefinitions.getMechanismProviderFilteringSaslServerFactory());
        resourceRegistration.registerSubModel(SaslServerDefinitions.getProviderSaslServerFactoryDefintion());
        resourceRegistration.registerSubModel(SaslServerDefinitions.getServiceLoaderSaslServerFactoryDefinition());

        // TLS Building Blocks
        resourceRegistration.registerSubModel(new KeyStoreDefinition());
    }

    static ServiceBuilder<?> commonDependencies(ServiceBuilder<?> serviceBuilder) {
        serviceBuilder.addDependencies(SecurityPropertyService.SERVICE_NAME);
        serviceBuilder.addDependencies(CoreService.SERVICE_NAME);
        return serviceBuilder;
    }

    private static void installService(ServiceName serviceName, Service<?> service, ServiceTarget serviceTarget) {
        serviceTarget.addService(serviceName, service)
            .setInitialMode(Mode.ACTIVE)
            .install();
    }

    private static SecurityPropertyService uninstallSecurityPropertyService(OperationContext context) {
        ServiceRegistry serviceRegistry = context.getServiceRegistry(true);

        ServiceController<?> service = serviceRegistry.getService(SecurityPropertyService.SERVICE_NAME);
        if (service != null) {
            Object serviceImplementation = service.getService();
            context.removeService(service);
            if (serviceImplementation != null && serviceImplementation instanceof SecurityPropertyService) {
                return (SecurityPropertyService) serviceImplementation;
            }
        }

        return null;
    }

    private static class ElytronAdd extends AbstractBoottimeAddStepHandler {

        private ElytronAdd() {
        }

        @Override
        protected void populateModel(ModelNode operation, ModelNode model) throws OperationFailedException {
            ROOT_LOGGER.iAmElytron();
        }

        @Override
        protected void performBoottime(OperationContext context, ModelNode operation, Resource resource)
                throws OperationFailedException {
            ServiceTarget target = context.getServiceTarget();
            installService(SecurityPropertyService.SERVICE_NAME, new SecurityPropertyService(), target);
            installService(CoreService.SERVICE_NAME, new CoreService(), target);
        }

        @Override
        protected void rollbackRuntime(OperationContext context, ModelNode operation, Resource resource) {
            uninstallSecurityPropertyService(context);
            context.removeService(CoreService.SERVICE_NAME);
        }

    }

    private static class ElytronRemove extends AbstractRemoveStepHandler {

        private ElytronRemove() {
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            SecurityPropertyService securityPropertyService = uninstallSecurityPropertyService(context);
            if (securityPropertyService != null) {
                context.attach(SECURITY_PROPERTY_SERVICE_KEY, securityPropertyService);
            }
            context.removeService(CoreService.SERVICE_NAME);
        }

        @Override
        protected void recoverServices(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget target = context.getServiceTarget();
            SecurityPropertyService securityPropertyService = context.getAttachment(SECURITY_PROPERTY_SERVICE_KEY);
            if (securityPropertyService != null) {
                installService(SecurityPropertyService.SERVICE_NAME, securityPropertyService, target);
            }
            installService(CoreService.SERVICE_NAME, new CoreService(), target);
        }

    }


}
