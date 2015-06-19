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
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;

import java.security.Principal;
import java.util.List;

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
import org.jboss.as.controller.SimpleOperationDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron._private.ElytronSubsystemMessages;
import org.wildfly.security.auth.login.SecurityDomain;
import org.wildfly.security.auth.login.SecurityIdentity;
import org.wildfly.security.auth.login.ServerAuthenticationContext;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A {@link ResourceDefinition} for a single domain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainDefinition extends SimpleResourceDefinition {

    private static final ServiceUtil<SecurityDomain> DOMAIN_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_DOMAIN_RUNTIME_CAPABILITY, ElytronDescriptionConstants.DOMAIN, SecurityDomain.class);
    private static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, null, SecurityRealm.class);

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
    private static final AuthenticatorOperationHandler AUTHENTICATE = new AuthenticatorOperationHandler();

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

    @Override
    public void registerOperations(ManagementResourceRegistration resourceRegistration) {
        super.registerOperations(resourceRegistration);
        registerAuthenticatorOperationHandler(resourceRegistration);
    }

    private void registerAuthenticatorOperationHandler(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerOperationHandler(new SimpleOperationDefinition(AUTHENTICATE.getOperationName(),getResourceDescriptionResolver(), AUTHENTICATE.getParameterDefinitions()), AUTHENTICATE);
    }

    private static ServiceController<SecurityDomain> installService(OperationContext context, ServiceName domainName, ModelNode model) throws OperationFailedException {
        ServiceTarget serviceTarget = context.getServiceTarget();
        String simpleName = domainName.getSimpleName();

        String defaultRealm = DomainDefinition.DEFAULT_REALM.resolveModelAttribute(context, model).asString();
        List<String> realms = DomainDefinition.REALMS.unwrap(context, model);

        DomainService domain = new DomainService(simpleName, defaultRealm);

        ServiceBuilder<SecurityDomain> domainBuilder = serviceTarget.addService(domainName, domain)
                .setInitialMode(Mode.ACTIVE);

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
        protected void populateModel(final OperationContext context, final ModelNode operation, final Resource resource)
                throws OperationFailedException {
            super.populateModel(context, operation, resource);

            ModelNode model = resource.getModel();
            String defaultRealm = DomainDefinition.DEFAULT_REALM.resolveModelAttribute(context, model).asString();
            List<String> realms = DomainDefinition.REALMS.unwrap(context, model);

            if (realms.contains(defaultRealm) == false) {
                throw ROOT_LOGGER.defaultRealmNotReferenced(defaultRealm);
            }
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

    /**
     * <p>A temporary operation that performs authentication based on a {@link SecurityDomain}. This operation will be removed once
     * the subsystem is fully functional. It should be used for <em>test</em> purposes only.
     *
     * <p>This operation is very verbose in order to push messages back to CLI during tests.
     */
    private static class AuthenticatorOperationHandler implements OperationStepHandler {

        private static final String OPERATION_NAME = "authenticate";
        private static final String PARAMETER_USERNAME = "username";
        private static final String PARAMETER_PASSWORD = "password";

        private static final SimpleAttributeDefinition USER_NAME = new SimpleAttributeDefinitionBuilder(PARAMETER_USERNAME, ModelType.STRING, false)
                .setAllowExpression(false)
                .build();

        private static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(PARAMETER_PASSWORD, ModelType.STRING, false)
                .setAllowExpression(false)
                .build();

        private AuthenticatorOperationHandler() {
            
        }

        @Override
        public void execute(OperationContext context, ModelNode operation) throws OperationFailedException {
            context.addStep((contextStep, operationStep) -> {
                String username = USER_NAME.resolveModelAttribute(context, operation).asString();
                String password = PASSWORD.resolveModelAttribute(context, operation).asString();
                SecurityDomain securityDomain = getSecurityDomain(context, operation);

                try {
                    ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();

                    authenticationContext.setAuthenticationName(username);

                    Principal authenticationPrincipal = authenticationContext.getAuthenticationPrincipal();

                    if (authenticationPrincipal == null) {
                        addFailureDescription("Invalid username [" + username + "].", context);
                        return;
                    }

                    // for now, only clear passwords. we can provide an enum with different types later. if necessary.
                    Class<ClearPassword> credentialType = ClearPassword.class;
                    CredentialSupport credentialSupport = authenticationContext.getCredentialSupport(credentialType);

                    if (!credentialSupport.mayBeVerifiable()) {
                        addFailureDescription("Credential type [" + credentialType + "] not verifiable.", context);
                        return;
                    }

                    PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                    Password clearPassword = passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray()));

                    if (authenticationContext.verifyCredential(clearPassword)) {
                        authenticationContext.succeed();

                        SecurityIdentity authorizedIdentity = authenticationContext.getAuthorizedIdentity();

                        if (authorizedIdentity == null) {
                            addFailureDescription("User [" + username + "] authenticated but no authorized identity could be obtained.", context);
                            return;
                        }

                        context.getResult().add("User [" + username + "] successfully authenticated. Roles are " + authorizedIdentity.getRoles() + ". Permissions are [" + authorizedIdentity.getPermissions() + "].");
                    } else {
                        authenticationContext.fail();
                        addFailureDescription("Invalid credentials for username [" + username + "].", context);
                    }
                } catch (Exception cause) {
                    addFailureDescription(cause.getMessage(), context);
                    ElytronSubsystemMessages.ROOT_LOGGER.error(cause);
                } finally {
                    context.completeStep(OperationContext.ResultHandler.NOOP_RESULT_HANDLER);
                }


            }, OperationContext.Stage.RUNTIME);
        }

        private void addFailureDescription(String message, OperationContext context) {
            ModelNode failureDescription = context.getFailureDescription();
            failureDescription.add(message);
        }

        private SecurityDomain getSecurityDomain(OperationContext context, ModelNode operation) {
            ServiceRegistry serviceRegistry = context.getServiceRegistry(false);
            ServiceController<SecurityDomain> serviceController = (ServiceController<SecurityDomain>) serviceRegistry.getRequiredService(DOMAIN_SERVICE_UTIL.serviceName(operation));
            Service<SecurityDomain> service = serviceController.getService();

            return service.getValue();
        }

        private static String getOperationName() {
            return OPERATION_NAME;
        }

        private static AttributeDefinition[] getParameterDefinitions() {
            return new AttributeDefinition[] {USER_NAME, PASSWORD};
        }
    }
}
