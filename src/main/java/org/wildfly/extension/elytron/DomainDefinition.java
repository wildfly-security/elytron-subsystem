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

import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PERMISSION_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PRINCIPAL_DECODER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.ROLE_DECODER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.ROLE_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.util.List;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.DomainService.RealmDependency;
import org.wildfly.extension.elytron.IdentityResourceDefinition.AuthenticatorOperationHandler;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;

/**
 * A {@link ResourceDefinition} for a single domain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainDefinition extends SimpleResourceDefinition {

    private static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, null, SecurityRealm.class);

    static final SimpleAttributeDefinition DEFAULT_REALM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DEFAULT_REALM, ModelType.STRING, false)
         .setAllowExpression(false)
         .setMinSize(1)
         .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
         .build();

    static final SimpleAttributeDefinition PRE_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRE_REALM_NAME_REWRITER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(NAME_REWRITER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition POST_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.POST_REALM_NAME_REWRITER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(NAME_REWRITER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PRINCIPAL_DECODER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL_DECODER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(PRINCIPAL_DECODER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition PERMISSION_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PERMISSION_MAPPER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(PERMISSION_MAPPER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition REALM_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM_MAPPER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(REALM_MAPPER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition ROLE_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ROLE_MAPPER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .setCapabilityReference(ROLE_MAPPER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition REALM_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM, ModelType.STRING, false)
        .setXmlName(ElytronDescriptionConstants.NAME)
        .setAllowExpression(true)
        .setMinSize(1)
        .setCapabilityReference(SECURITY_REALM_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME_REWRITER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setCapabilityReference(NAME_REWRITER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final SimpleAttributeDefinition REALM_ROLE_DECODER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ROLE_DECODER, ModelType.STRING, true)
        .setAllowExpression(true)
        .setMinSize(1)
        .setCapabilityReference(ROLE_DECODER_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
        .build();

    static final ObjectTypeAttributeDefinition REALM = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.REALM, REALM_NAME, REALM_NAME_REWRITER, REALM_ROLE_DECODER, ROLE_MAPPER)
        .build();

    static final ObjectListAttributeDefinition REALMS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.REALMS, REALM)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final StringListAttributeDefinition TRUSTED_SECURITY_DOMAINS = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.TRUSTED_SECURITY_DOMAINS)
            .setAllowNull(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SECURITY_DOMAIN_CAPABILITY, true)
            .build();

    private static final AttributeDefinition[] ATTRIBUTES =
            new AttributeDefinition[] { PRE_REALM_NAME_REWRITER, POST_REALM_NAME_REWRITER, PRINCIPAL_DECODER, REALM_MAPPER, ROLE_MAPPER, PERMISSION_MAPPER, DEFAULT_REALM, REALMS, TRUSTED_SECURITY_DOMAINS };

    private static final DomainAddHandler ADD = new DomainAddHandler();
    private static final OperationStepHandler REMOVE = new SingleCapabilityServiceRemoveHandler<SecurityDomain>(ADD, SECURITY_DOMAIN_RUNTIME_CAPABILITY, SecurityDomain.class);
    private static final WriteAttributeHandler WRITE = new WriteAttributeHandler(ElytronDescriptionConstants.SECURITY_DOMAIN);
    private static final AuthenticatorOperationHandler AUTHENTICATE = new AuthenticatorOperationHandler();

    DomainDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.SECURITY_DOMAIN), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.SECURITY_DOMAIN))
            .setAddHandler(ADD)
            .setRemoveHandler(REMOVE)
            .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
            .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(current, null, WRITE);
        }
    }

    @Override
    public void registerCapabilities(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerCapability(SECURITY_DOMAIN_RUNTIME_CAPABILITY);
    }

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        registerIdentityManagementOperations(resourceRegistration);
    }

    private void registerIdentityManagementOperations(ManagementResourceRegistration resourceRegistration) {
        IdentityResourceDefinition.ReadSecurityDomainIdentityHandler.register(resourceRegistration, getResourceDescriptionResolver());
        IdentityResourceDefinition.AuthenticatorOperationHandler.register(resourceRegistration, getResourceDescriptionResolver());
    }

    private static ServiceController<SecurityDomain> installService(OperationContext context, ServiceName domainName, ModelNode model) throws OperationFailedException {
        ServiceTarget serviceTarget = context.getServiceTarget();
        String simpleName = domainName.getSimpleName();

        String defaultRealm = DomainDefinition.DEFAULT_REALM.resolveModelAttribute(context, model).asString();
        List<ModelNode> realms = REALMS.resolveModelAttribute(context, model).asList();
        List<String> trustedSecurityDomains = TRUSTED_SECURITY_DOMAINS.unwrap(context, model);

        String preRealmNameRewriter = asStringIfDefined(context, PRE_REALM_NAME_REWRITER, model);
        String postRealmNameRewriter = asStringIfDefined(context, POST_REALM_NAME_REWRITER, model);
        String principalDecoder = asStringIfDefined(context, PRINCIPAL_DECODER, model);
        String permissionMapper = asStringIfDefined(context, PERMISSION_MAPPER, model);
        String realmMapper = asStringIfDefined(context, REALM_MAPPER, model);
        String roleMapper = asStringIfDefined(context, ROLE_MAPPER, model);

        DomainService domain = new DomainService(simpleName, defaultRealm, trustedSecurityDomains);

        ServiceBuilder<SecurityDomain> domainBuilder = serviceTarget.addService(domainName, domain)
                .setInitialMode(Mode.ACTIVE);

        if (preRealmNameRewriter != null) {
            injectNameRewriter(preRealmNameRewriter, context, domainBuilder, domain.createPreRealmNameRewriterInjector(preRealmNameRewriter));
        }
        if (postRealmNameRewriter != null) {
            injectNameRewriter(postRealmNameRewriter, context, domainBuilder, domain.createPostRealmNameRewriterInjector(postRealmNameRewriter));
        }
        if (principalDecoder != null) {
            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(PRINCIPAL_DECODER_CAPABILITY, principalDecoder);
            ServiceName principalDecoderServiceName = context.getCapabilityServiceName(runtimeCapability, PrincipalDecoder.class);

            domainBuilder.addDependency(principalDecoderServiceName, PrincipalDecoder.class, domain.getPrincipalDecoderInjector());
        }
        if (permissionMapper != null) {
            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(PERMISSION_MAPPER_CAPABILITY, permissionMapper);
            ServiceName permissionMapperServiceName = context.getCapabilityServiceName(runtimeCapability, PermissionMapper.class);

            domainBuilder.addDependency(permissionMapperServiceName, PermissionMapper.class, domain.getPermissionMapperInjector());
        }
        if (realmMapper != null) {
            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(REALM_MAPPER_CAPABILITY, realmMapper);
            ServiceName realmMapperServiceName = context.getCapabilityServiceName(runtimeCapability, RealmMapper.class);

            domainBuilder.addDependency(realmMapperServiceName, RealmMapper.class, domain.getRealmMapperInjector());
        }
        if (roleMapper != null) {
            injectRoleMapper(roleMapper, context, domainBuilder, domain.createDomainRoleMapperInjector(roleMapper));
        }

        for (ModelNode current : realms) {
            String realmName = REALM_NAME.resolveModelAttribute(context, current).asString();
            String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(SECURITY_REALM_CAPABILITY, realmName);
            ServiceName realmServiceName = context.getCapabilityServiceName(runtimeCapability, SecurityRealm.class);

            RealmDependency realmDependency = domain.createRealmDependency(realmName);
            REALM_SERVICE_UTIL.addInjection(domainBuilder, realmDependency.getSecurityRealmInjector() , realmServiceName);

            String nameRewriter = asStringIfDefined(context, REALM_NAME_REWRITER, current);
            if (nameRewriter != null) {
                Injector<NameRewriter> nameRewriterInjector = realmDependency.getNameRewriterInjector(nameRewriter);
                injectNameRewriter(nameRewriter, context, domainBuilder, nameRewriterInjector);
            }
            String realmRoleMapper = asStringIfDefined(context, ROLE_MAPPER, current);
            if (realmRoleMapper != null) {
                injectRoleMapper(realmRoleMapper, context, domainBuilder, realmDependency.getRoleMapperInjector(realmRoleMapper));
            }
            String realmRoleDecoder = asStringIfDefined(context, REALM_ROLE_DECODER, current);
            if (realmRoleDecoder != null) {
                injectRoleDecoder(realmRoleDecoder, context, domainBuilder, realmDependency.getRoleDecoderInjector(realmRoleDecoder));
            }
        }

        commonDependencies(domainBuilder);
        return domainBuilder.install();
    }

    private static void injectNameRewriter(String nameRewriter, OperationContext context, ServiceBuilder<SecurityDomain> domainBuilder, Injector<NameRewriter> injector) {
        if (nameRewriter == null) {
            return;
        }

        if (injector == null) {
            // Service did not supply one as one is already present for this name.
            return;
        }

        String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(NAME_REWRITER_CAPABILITY, nameRewriter);
        ServiceName nameRewriterServiceName = context.getCapabilityServiceName(runtimeCapability, NameRewriter.class);

        domainBuilder.addDependency(nameRewriterServiceName, NameRewriter.class, injector);
    }

    private static void injectRoleMapper(String roleMapper, OperationContext context, ServiceBuilder<SecurityDomain> domainBuilder, Injector<RoleMapper> injector) {
        if (roleMapper == null) {
            return;
        }

        if (injector == null) {
            // Service did not supply one as one is already present for this name.
            return;
        }

        String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(ROLE_MAPPER_CAPABILITY, roleMapper);
        ServiceName roleMapperServiceName = context.getCapabilityServiceName(runtimeCapability, RoleMapper.class);

        domainBuilder.addDependency(roleMapperServiceName, RoleMapper.class, injector);
    }

    private static void injectRoleDecoder(String roleDecoder, OperationContext context, ServiceBuilder<SecurityDomain> domainBuilder, Injector<RoleDecoder> injector) {
        if (roleDecoder == null) {
            return;
        }
        if (injector == null) {
            return;
        }
        String runtimeCapability = RuntimeCapability.buildDynamicCapabilityName(ROLE_DECODER_CAPABILITY, roleDecoder);
        ServiceName roleDecoderServiceName = context.getCapabilityServiceName(runtimeCapability, RoleDecoder.class);
        domainBuilder.addDependency(roleDecoderServiceName, RoleDecoder.class, injector);
    }

    private static class DomainAddHandler extends BaseAddHandler {

        private DomainAddHandler() {
            super(SECURITY_DOMAIN_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void populateModel(final OperationContext context, final ModelNode operation, final Resource resource)
                throws OperationFailedException {
            super.populateModel(context, operation, resource);

            ModelNode model = resource.getModel();
            String defaultRealm = DomainDefinition.DEFAULT_REALM.resolveModelAttribute(context, model).asString();

            List<ModelNode> realms = REALMS.resolveModelAttribute(context, model).asList();
            boolean defaultFound = false;
            for (ModelNode current : realms) {
                String realmName = REALM_NAME.resolveModelAttribute(context, current).asString();
                if (defaultRealm.equals(realmName)) {
                    defaultFound = true;
                    break;
                }
            }

            if (defaultFound == false) {
                throw ROOT_LOGGER.defaultRealmNotReferenced(defaultRealm);
            }
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            RuntimeCapability<Void> runtimeCapability = SECURITY_DOMAIN_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName domainName = runtimeCapability.getCapabilityServiceName(SecurityDomain.class);

            installService(context, domainName, model);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        public WriteAttributeHandler(String parentKeyName) {
            super(parentKeyName, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return SECURITY_DOMAIN_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(SecurityDomain.class);
        }


        @Override
        protected void recreateParentService(OperationContext context, PathAddress parentAddress, ModelNode parentModel)
                throws OperationFailedException {
            installService(context, getParentServiceName(parentAddress), parentModel);
        }

    }
}

