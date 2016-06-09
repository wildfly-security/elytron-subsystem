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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_FACTORY_CREDENTIAL_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.RELATIVE_TO;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathName;
import static org.wildfly.extension.elytron.FileAttributeDefinitions.pathResolver;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.services.path.PathManager;
import org.jboss.as.controller.services.path.PathManagerService;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.StartException;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.FileAttributeDefinitions.PathResolver;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.util.GSSCredentialSecurityFactory;

/**
 * Factory class for the Kerberos security factory resource.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KerberosSecurityFactoryDefinition {

    static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder(FileAttributeDefinitions.PATH)
        .setAllowNull(false)
        .build();

    static final SimpleAttributeDefinition PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition MINIMUM_REMAINING_LIFETIME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MINIMUM_REMAINING_LIFETIME, ModelType.INT, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(0))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition REQUEST_LIFETIME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REQUEST_LIFETIME, ModelType.INT, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(GSSCredential.INDEFINITE_LIFETIME))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition SERVER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SERVER, ModelType.BOOLEAN, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(true))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition DEBUG = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DEBUG, ModelType.STRING, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(false))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final StringListAttributeDefinition MECHANISM_OIDS = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_OIDS)
        .setAllowExpression(true)
        .setAllowNull(false)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static ResourceDefinition getKerberosSecurityFactoryDefinition() {
        final AttributeDefinition[] attributes = new AttributeDefinition[] { PRINCIPAL, RELATIVE_TO, PATH,  MINIMUM_REMAINING_LIFETIME, REQUEST_LIFETIME, SERVER, DEBUG, MECHANISM_OIDS };
        TrivialAddHandler<SecurityFactory> add = new TrivialAddHandler<SecurityFactory>(SecurityFactory.class, attributes, SECURITY_FACTORY_CREDENTIAL_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<SecurityFactory> getValueSupplier(ServiceBuilder<SecurityFactory> serviceBuilder, OperationContext context, ModelNode model) throws OperationFailedException {
                final String principal = PRINCIPAL.resolveModelAttribute(context, model).asString();
                final int minimumRemainingLifetime = MINIMUM_REMAINING_LIFETIME.resolveModelAttribute(context, model).asInt();
                final int requestLifetime = REQUEST_LIFETIME.resolveModelAttribute(context, model).asInt();
                final boolean server = SERVER.resolveModelAttribute(context, model).asBoolean();
                final boolean debug = DEBUG.resolveModelAttribute(context, model).asBoolean();
                final List<Oid> mechanaismOids = MECHANISM_OIDS.unwrap(context, model).stream().map(s -> {
                    try {
                        return new Oid(s);
                    } catch (GSSException e) {
                        throw new IllegalArgumentException(e);
                    }
                }).collect(Collectors.toList());
                final InjectedValue<PathManager> pathManager = new InjectedValue<PathManager>();

                final String path = PATH.resolveModelAttribute(context, model).asString();
                final String relativeTo = asStringIfDefined(context, RELATIVE_TO, model);

                if (relativeTo != null) {
                    serviceBuilder.addDependency(PathManagerService.SERVICE_NAME, PathManager.class, pathManager);
                    serviceBuilder.addDependency(pathName(relativeTo));
                }

                return () -> {
                    PathResolver pathResolver = pathResolver();
                    pathResolver.path(path);
                    if (relativeTo != null) {
                        pathResolver.relativeTo(relativeTo, pathManager.getValue());
                    }
                    File resolvedPath = pathResolver.resolve();

                    GSSCredentialSecurityFactory.Builder builder =  GSSCredentialSecurityFactory.builder()
                        .setPrincipal(principal)
                        .setKeyTab(resolvedPath)
                        .setMinimumRemainingLifetime(minimumRemainingLifetime)
                        .setRequestLifetime(requestLifetime)
                        .setIsServer(server)
                        .setDebug(debug);
                    mechanaismOids.forEach(builder::addMechanismOid);

                    try {
                        return builder.build();
                    } catch (IOException e) {
                        throw new StartException(e);
                    }
                };
            }
        };

        return new TrivialResourceDefinition(ElytronDescriptionConstants.KERBEROS_SECURITY_FACTORY, add, attributes, SECURITY_FACTORY_CREDENTIAL_RUNTIME_CAPABILITY);
    }

}
