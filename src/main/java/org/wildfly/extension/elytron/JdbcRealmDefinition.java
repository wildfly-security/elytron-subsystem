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

import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.BCRYPT_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CLEAR_PASSWORD_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SALTED_SIMPLE_DIGEST_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SCRAM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SIMPLE_DIGEST_MAPPER;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
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
import org.jboss.as.controller.logging.ControllerLogger;
import org.jboss.as.controller.operations.validation.AllowedValuesValidator;
import org.jboss.as.controller.operations.validation.ModelTypeValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.dmr.Property;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.security.auth.provider.jdbc.KeyMapper;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;

/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} backed by a database using JDBC.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class JdbcRealmDefinition extends SimpleResourceDefinition {

    static final ServiceUtil<SecurityRealm> REALM_SERVICE_UTIL = ServiceUtil.newInstance(SECURITY_REALM_RUNTIME_CAPABILITY, ElytronDescriptionConstants.JDBC_REALM, SecurityRealm.class);

    /**
     * {@link ElytronDescriptionConstants#CLEAR_PASSWORD_MAPPER} complex attribute;
     */
    static class ClearPasswordObjectDefinition implements PasswordMapperObjectDefinition {
        static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
                .setDefaultValue(new ModelNode(ClearPassword.ALGORITHM_CLEAR))
                .setValidator(new StringValuesValidator(ClearPassword.ALGORITHM_CLEAR))
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD_INDEX, ModelType.INT, false)
                .setMinSize(1)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectTypeAttributeDefinition CLEAR_PASSWORD = new ObjectTypeAttributeDefinition.Builder(
                ElytronDescriptionConstants.CLEAR_PASSWORD_MAPPER, PASSWORD)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getResourceDefinition() {
            return CLEAR_PASSWORD;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return new SimpleAttributeDefinition[] {ALGORITHM, PASSWORD};
        }

        @Override
        public PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException {
            String algorithm = ElytronExtension.asStringIfDefined(context, ALGORITHM, propertyNode);
            int password = ElytronExtension.asIntIfDefined(context, PASSWORD, propertyNode);

            return new PasswordKeyMapper(algorithm, password);
        }
    }

    /**
     * {@link ElytronDescriptionConstants#BCRYPT_MAPPER} complex attribute;
     */
    static class BcryptPasswordObjectDefinition implements PasswordMapperObjectDefinition {
        static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
                .setDefaultValue(new ModelNode(BCryptPassword.ALGORITHM_BCRYPT))
                .setValidator(new StringValuesValidator(BCryptPassword.ALGORITHM_BCRYPT))
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD_INDEX, ModelType.INT, false)
                .setMinSize(1)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition ITERATION_COUNT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ITERATION_COUNT_INDEX, ModelType.INT, false)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SALT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SALT_INDEX, ModelType.INT, false)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectTypeAttributeDefinition BCRYPT = new ObjectTypeAttributeDefinition.Builder(
                ElytronDescriptionConstants.BCRYPT_MAPPER, PASSWORD, SALT, ITERATION_COUNT)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getResourceDefinition() {
            return BCRYPT;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return new SimpleAttributeDefinition[] {ALGORITHM, PASSWORD, SALT, ITERATION_COUNT};
        }

        @Override
        public PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException {
            String algorithm = ElytronExtension.asStringIfDefined(context, ALGORITHM, propertyNode);
            int password = ElytronExtension.asIntIfDefined(context, PASSWORD, propertyNode);
            int salt = ElytronExtension.asIntIfDefined(context, SALT, propertyNode);
            int iterationCount = ElytronExtension.asIntIfDefined(context, ITERATION_COUNT, propertyNode);

            return new PasswordKeyMapper(algorithm, password, salt, iterationCount);
        }
    }

    /**
     * {@link ElytronDescriptionConstants#SALTED_SIMPLE_DIGEST_MAPPER} complex attribute;
     */
    static class SaltedSimpleDigestObjectDefinition implements PasswordMapperObjectDefinition {
        static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
                .setDefaultValue(new ModelNode(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5))
                .setValidator(new StringValuesValidator(
                        SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5,
                        SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1,
                        SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256,
                        SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384,
                        SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512,
                        SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_MD5,
                        SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1,
                        SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256,
                        SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384,
                        SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512
                ))
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD_INDEX, ModelType.INT, false)
                .setMinSize(1)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SALT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SALT_INDEX, ModelType.INT, false)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectTypeAttributeDefinition SALTED_SIMPLE_DIGEST = new ObjectTypeAttributeDefinition.Builder(
                ElytronDescriptionConstants.SALTED_SIMPLE_DIGEST_MAPPER, ALGORITHM, PASSWORD, SALT)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getResourceDefinition() {
            return SALTED_SIMPLE_DIGEST;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return new SimpleAttributeDefinition[] {ALGORITHM, PASSWORD, SALT};
        }

        @Override
        public PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException {
            String algorithm = ElytronExtension.asStringIfDefined(context, ALGORITHM, propertyNode);
            int password = ElytronExtension.asIntIfDefined(context, PASSWORD, propertyNode);
            int salt = ElytronExtension.asIntIfDefined(context, SALT, propertyNode);

            return new PasswordKeyMapper(algorithm, password, salt);
        }
    }

    /**
     * {@link ElytronDescriptionConstants#SIMPLE_DIGEST_MAPPER} complex attribute;
     */
    static class SimpleDigestMapperObjectDefinition implements PasswordMapperObjectDefinition {
        static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
                .setDefaultValue(new ModelNode(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5))
                .setValidator(new StringValuesValidator(
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2,
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5,
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1,
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256,
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384,
                        SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512
                ))
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD_INDEX, ModelType.INT, false)
                .setMinSize(1)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectTypeAttributeDefinition SIMPLE_DIGEST = new ObjectTypeAttributeDefinition.Builder(
                ElytronDescriptionConstants.SIMPLE_DIGEST_MAPPER, ALGORITHM, PASSWORD)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getResourceDefinition() {
            return SIMPLE_DIGEST;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return new SimpleAttributeDefinition[] {ALGORITHM, PASSWORD};
        }

        @Override
        public PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException {
            String algorithm = ElytronExtension.asStringIfDefined(context, ALGORITHM, propertyNode);
            int password = ElytronExtension.asIntIfDefined(context, PASSWORD, propertyNode);

            return new PasswordKeyMapper(algorithm, password);
        }
    }

    /**
     * {@link ElytronDescriptionConstants#SCRAM_MAPPER} complex attribute;
     */
    static class ScramMapperObjectDefinition implements PasswordMapperObjectDefinition {
        static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING, false)
                .setDefaultValue(new ModelNode(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256))
                .setValidator(new StringValuesValidator(
                        ScramDigestPassword.ALGORITHM_SCRAM_SHA_1,
                        ScramDigestPassword.ALGORITHM_SCRAM_SHA_256
                ))
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PASSWORD = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PASSWORD_INDEX, ModelType.INT, false)
                .setMinSize(1)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition ITERATION_COUNT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ITERATION_COUNT_INDEX, ModelType.INT, false)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SALT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SALT_INDEX, ModelType.INT, false)
                .setAllowExpression(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final ObjectTypeAttributeDefinition SCRAM = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.SCRAM_MAPPER, ALGORITHM, PASSWORD, SALT, ITERATION_COUNT)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        @Override
        public ObjectTypeAttributeDefinition getResourceDefinition() {
            return SCRAM;
        }

        @Override
        public SimpleAttributeDefinition[] getAttributes() {
            return new SimpleAttributeDefinition[] {ALGORITHM, PASSWORD, SALT, ITERATION_COUNT};
        }

        @Override
        public PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException {
            String algorithm = ElytronExtension.asStringIfDefined(context, ALGORITHM, propertyNode);
            int password = ElytronExtension.asIntIfDefined(context, PASSWORD, propertyNode);
            int salt = ElytronExtension.asIntIfDefined(context, SALT, propertyNode);
            int iterationCount = ElytronExtension.asIntIfDefined(context, ITERATION_COUNT, propertyNode);

            return new PasswordKeyMapper(algorithm, password, salt, iterationCount);
        }
    }

    interface PasswordMapperObjectDefinition {
        ObjectTypeAttributeDefinition getResourceDefinition();
        SimpleAttributeDefinition[] getAttributes();
        PasswordKeyMapper toPasswordKeyMapper(OperationContext context, ModelNode propertyNode) throws OperationFailedException, InvalidKeyException;
    }

    /**
     * {@link ElytronDescriptionConstants#AUTHENTICATION_QUERY} complex attribute.
     */
    static class AuthenticationQueryAttributes {
        static final SimpleAttributeDefinition SQL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SQL, ModelType.STRING, false)
                .setAllowExpression(false)
                .setMinSize(1)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition DATA_SOURCE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.DATA_SOURCE, ModelType.STRING, false)
                .setAllowExpression(false)
                .setMinSize(1)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilityReference(Capabilities.DATA_SOURCE_CAPABILITY_NAME, Capabilities.SECURITY_REALM_CAPABILITY, true)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {SQL, DATA_SOURCE};

        static Map<String, PasswordMapperObjectDefinition> SUPPORTED_PASSWORD_MAPPERS;

        static {
            Map<String, PasswordMapperObjectDefinition> supportedMappers = new HashMap<>();

            supportedMappers.put(CLEAR_PASSWORD_MAPPER, new ClearPasswordObjectDefinition());
            supportedMappers.put(BCRYPT_MAPPER, new BcryptPasswordObjectDefinition());
            supportedMappers.put(SALTED_SIMPLE_DIGEST_MAPPER, new SaltedSimpleDigestObjectDefinition());
            supportedMappers.put(SIMPLE_DIGEST_MAPPER, new SimpleDigestMapperObjectDefinition());
            supportedMappers.put(SCRAM_MAPPER, new ScramMapperObjectDefinition());

            SUPPORTED_PASSWORD_MAPPERS = Collections.unmodifiableMap(supportedMappers);
        }

        static final ObjectTypeAttributeDefinition AUTHENTICATION_QUERY = new ObjectTypeAttributeDefinition.Builder(
                ElytronDescriptionConstants.AUTHENTICATION_QUERY,
                SQL,
                DATA_SOURCE,
                ClearPasswordObjectDefinition.CLEAR_PASSWORD,
                BcryptPasswordObjectDefinition.BCRYPT,
                SaltedSimpleDigestObjectDefinition.SALTED_SIMPLE_DIGEST,
                SimpleDigestMapperObjectDefinition.SIMPLE_DIGEST,
                ScramMapperObjectDefinition.SCRAM)
                .setAllowNull(false)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();
    }

    /**
     * A simple {@link ModelTypeValidator} that requires that values are contained on a pre-defined list of string.
     *
     * //TODO: couldn't find a built-in validator for that. see if there is one or even if it can be moved to its own file.
     */
    static class StringValuesValidator extends ModelTypeValidator implements AllowedValuesValidator {

        private List<ModelNode> allowedValues = new ArrayList<>();

        public StringValuesValidator(String... values) {
            super(ModelType.STRING);
            for (String value : values) {
                allowedValues.add(new ModelNode().set(value));
            }
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                if (!allowedValues.contains(value)) {
                    throw new OperationFailedException(ControllerLogger.ROOT_LOGGER.invalidValue(value.asString(), parameterName, allowedValues));
                }
            }
        }

        @Override
        public List<ModelNode> getAllowedValues() {
            return this.allowedValues;
        }
    }

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] {AuthenticationQueryAttributes.AUTHENTICATION_QUERY};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new RealmRemoveHandler(ADD);
    private static final OperationStepHandler WRITE = new WriteAttributeHandler();

    JdbcRealmDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.JDBC_REALM),
                ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.JDBC_REALM),
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

    private static class RealmAddHandler extends AbstractAddStepHandler {

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = RuntimeCapability.fromBaseCapability(SECURITY_REALM_RUNTIME_CAPABILITY, context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(SecurityRealm.class);
            ModelNode authenticationQueryNode = AuthenticationQueryAttributes.AUTHENTICATION_QUERY.resolveModelAttribute(context, operation);
            String authenticationQuerySql = asStringIfDefined(context, AuthenticationQueryAttributes.SQL, authenticationQueryNode);
            List<KeyMapper> keyMappers = resolveKeyMappers(context, authenticationQueryNode);
            JdbcRealmService service = new JdbcRealmService(authenticationQuerySql, keyMappers);
            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(realmName, service);

            configureDependencies(context, authenticationQueryNode, service, serviceBuilder)
                    .setInitialMode(ServiceController.Mode.ACTIVE)
                    .install();
        }

        private ServiceBuilder<?> configureDependencies(OperationContext context, ModelNode authenticationQueryNode, JdbcRealmService service, ServiceBuilder<SecurityRealm> serviceBuilder) throws OperationFailedException {
            String dataSource = asStringIfDefined(context, AuthenticationQueryAttributes.DATA_SOURCE, authenticationQueryNode);
            String capabilityName = Capabilities.DATA_SOURCE_CAPABILITY_NAME + "." + dataSource;
            ServiceName dataSourceServiceName = context.getCapabilityServiceName(capabilityName, DataSource.class);

            return commonDependencies(serviceBuilder)
                    .addDependency(dataSourceServiceName, DataSource.class, service.getDataSourceInjectedValue());
        }

        private List<KeyMapper> resolveKeyMappers(OperationContext context, ModelNode authenticationQueryNode) throws OperationFailedException {
            List<KeyMapper> keyMappers = new ArrayList<>();

            for (Property property : authenticationQueryNode.asPropertyList()) {
                String name = property.getName();
                ModelNode propertyNode = property.getValue();
                PasswordMapperObjectDefinition mapperResource = AuthenticationQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.get(name);

                if (mapperResource == null) {
                    continue;
                }

                try {
                    keyMappers.add(mapperResource.toPasswordKeyMapper(context, propertyNode));
                } catch (InvalidKeyException e) {
                    throw new OperationFailedException("Invalid key type.", e);
                }
            }

            return keyMappers;
        }
    }

    private static class RealmRemoveHandler extends ServiceRemoveStepHandler {

        public RealmRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, SECURITY_REALM_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return REALM_SERVICE_UTIL.serviceName(name);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.JDBC_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress arg0) {
            return null;
        }
    }
}
