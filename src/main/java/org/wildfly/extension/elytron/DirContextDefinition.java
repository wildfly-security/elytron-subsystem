/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import static org.wildfly.extension.elytron.Capabilities.DIR_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.DIR_CONTEXT_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SSL_CONTEXT_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.security.auth.realm.ldap.DirContextFactory.ReferralMode;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
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
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.realm.ldap.DirContextFactory;
import org.wildfly.security.auth.realm.ldap.SimpleDirContextFactoryBuilder;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.net.ssl.SSLContext;
import java.util.Properties;

/**
 * A {@link ResourceDefinition} for a {@link javax.naming.directory.DirContext}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class DirContextDefinition extends SimpleResourceDefinition {

    public static final String CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

    static final SimpleAttributeDefinition URL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.URL, ModelType.STRING, true)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition AUTHENTICATION_LEVEL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AUTHENTICATION_LEVEL, ModelType.STRING, true)
            .setDefaultValue(new ModelNode("simple"))
            .setAllowedValues("none", "simple", "strong")
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL, ModelType.STRING, true)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition CREDENTIAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREDENTIAL, ModelType.STRING, true)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition ENABLE_CONNECTION_POOLING = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ENABLE_CONNECTION_POOLING, ModelType.BOOLEAN, true)
            .setDefaultValue(new ModelNode(false))
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition REFERRAL_MODE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REFERRAL_MODE, ModelType.STRING, true)
            .setDefaultValue(new ModelNode(ReferralMode.IGNORE.name()))
            .setAllowedValues(ReferralMode.FOLLOW.name(), ReferralMode.IGNORE.name(), ReferralMode.THROW.name())
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition SSL_CONTEXT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SSL_CONTEXT, ModelType.STRING, true)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(SSL_CONTEXT_CAPABILITY, DIR_CONTEXT_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {URL, AUTHENTICATION_LEVEL, PRINCIPAL, CREDENTIAL, ENABLE_CONNECTION_POOLING, REFERRAL_MODE, SSL_CONTEXT};

    DirContextDefinition() {
        super(new SimpleResourceDefinition.Parameters(PathElement.pathElement(ElytronDescriptionConstants.DIR_CONTEXT), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.DIR_CONTEXT))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilities(DIR_CONTEXT_RUNTIME_CAPABILITY));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition current : ATTRIBUTES) {
            resourceRegistration.registerReadOnlyAttribute(current, null);
        }
    }

    private static TrivialService.ValueSupplier<ExceptionSupplier<DirContext, NamingException>> obtainDirContextSupplier(final OperationContext context, final ModelNode model, final InjectedValue<SSLContext> sslContextInjector) throws OperationFailedException {

        String url = URL.resolveModelAttribute(context, model).asString();
        String authenticationLevel = AUTHENTICATION_LEVEL.resolveModelAttribute(context, model).asString();
        String principal = PRINCIPAL.resolveModelAttribute(context, model).asString();
        String credential = CREDENTIAL.resolveModelAttribute(context, model).asString();

        Properties connectionProperties = new Properties();
        ModelNode enableConnectionPoolingNode = ENABLE_CONNECTION_POOLING.resolveModelAttribute(context, model);
        connectionProperties.put(CONNECTION_POOLING_PROPERTY, enableConnectionPoolingNode.asBoolean());
        ReferralMode referralMode = ReferralMode.valueOf(REFERRAL_MODE.resolveModelAttribute(context, model).asString());

        return () -> {
            SimpleDirContextFactoryBuilder builder = SimpleDirContextFactoryBuilder.builder()
                    .setProviderUrl(url)
                    .setSecurityAuthentication(authenticationLevel)
                    .setSecurityPrincipal(principal)
                    .setSecurityCredential(credential)
                    .setConnectionProperties(connectionProperties);

            SSLContext sslContext = sslContextInjector.getOptionalValue();
            if (sslContext != null) builder.setSocketFactory(sslContext.getSocketFactory());

            DirContextFactory dirContextFactory = builder.build();
            return () -> dirContextFactory.obtainDirContext(referralMode);
        };
    }

    private static final AbstractAddStepHandler ADD = new AbstractAddStepHandler(DIR_CONTEXT_RUNTIME_CAPABILITY, ATTRIBUTES) {
        protected void performRuntime(final OperationContext context, final ModelNode operation, final ModelNode model) throws OperationFailedException {

            RuntimeCapability<Void> runtimeCapability = DIR_CONTEXT_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName serviceName = runtimeCapability.getCapabilityServiceName(ExceptionSupplier.class);

            final InjectedValue<SSLContext> sslContextInjector = new InjectedValue<>();

            TrivialService<ExceptionSupplier<DirContext, NamingException>> service = new TrivialService<>(obtainDirContextSupplier(context, model, sslContextInjector));
            ServiceBuilder<ExceptionSupplier<DirContext, NamingException>> serviceBuilder = context.getServiceTarget().addService(serviceName, service);

            String sslContextName = asStringIfDefined(context, SSL_CONTEXT, model);
            if (sslContextName != null) {
                String sslCapability = RuntimeCapability.buildDynamicCapabilityName(SSL_CONTEXT_CAPABILITY, sslContextName);
                ServiceName sslServiceName = context.getCapabilityServiceName(sslCapability, SSLContext.class);
                serviceBuilder.addDependency(sslServiceName, SSLContext.class, sslContextInjector);
            }

            serviceBuilder
                    .setInitialMode(ServiceController.Mode.ACTIVE)
                    .install();
        }
    };

    private static final OperationStepHandler REMOVE = new TrivialCapabilityServiceRemoveHandler(ADD, DIR_CONTEXT_RUNTIME_CAPABILITY);

}
