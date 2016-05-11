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

import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.CLASS_NAME;
import static org.wildfly.extension.elytron.ClassLoadingAttributeDefinitions.MODULE;

import static org.wildfly.extension.elytron.Capabilities.PERMISSION_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.PERMISSION_MAPPER_RUNTIME_CAPABILITY;

import java.util.Locale;
import java.util.function.BinaryOperator;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.operations.validation.EnumValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.SimplePermissionMapper;

/**
 * Definitions for resources describing {@link PermissionMapper} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class PermissionMapperDefinitions {

    static final SimpleAttributeDefinition LEFT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.LEFT, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(PERMISSION_MAPPER_CAPABILITY, PERMISSION_MAPPER_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition RIGHT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.RIGHT, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(PERMISSION_MAPPER_CAPABILITY, PERMISSION_MAPPER_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition LOGICAL_OPERATION = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.LOGICAL_OPERATION, ModelType.STRING, false)
            .setAllowExpression(true)
            .setAllowedValues(ElytronDescriptionConstants.AND, ElytronDescriptionConstants.OR, ElytronDescriptionConstants.XOR, ElytronDescriptionConstants.UNLESS)
            .setValidator(EnumValidator.create(LogicalMapperOperation.class, false, true))
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition MAPPING_MODE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MAPPING_MODE, ModelType.STRING, false)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode(ElytronDescriptionConstants.FIRST))
            .setAllowedValues(ElytronDescriptionConstants.AND, ElytronDescriptionConstants.OR, ElytronDescriptionConstants.XOR, ElytronDescriptionConstants.UNLESS, ElytronDescriptionConstants.FIRST)
            .setValidator(EnumValidator.create(MappingMode.class, false, true))
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final StringListAttributeDefinition PRINCIPALS = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.PRINCIPALS)
            .setAllowExpression(true)
            .setMinSize(1)
            .build();

    static final StringListAttributeDefinition ROLES = new StringListAttributeDefinition.Builder(ElytronDescriptionConstants.ROLES)
            .setAllowExpression(true)
            .setMinSize(1)
            .build();

    static final ObjectTypeAttributeDefinition CRITERIA = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.CRITERIA, PRINCIPALS, ROLES)
            .build();

    static final SimpleAttributeDefinition TARGET_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TARGET_NAME, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .build();

    static final SimpleAttributeDefinition ACTION = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ACTION, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .build();

    static final ObjectTypeAttributeDefinition PERMISSION = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.PERMISSION, CLASS_NAME, MODULE, TARGET_NAME, ACTION)
            .build();

    static final ObjectListAttributeDefinition PERMISSIONS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.PERMISSIONS, PERMISSION)
            .build();

    static final ObjectTypeAttributeDefinition PERMISSION_MAPPING = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.PERMISSION_MAPPING, CRITERIA, PERMISSIONS)
            .build();

    static final ObjectListAttributeDefinition PERMISSION_MAPPINGS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.PERMISSION_MAPPINGS, PERMISSION_MAPPING)
            .build();

    static ResourceDefinition getLogicalPermissionMapper() {
        AttributeDefinition[] attributes = new AttributeDefinition[] {LOGICAL_OPERATION, LEFT, RIGHT};
        TrivialAddHandler<PermissionMapper> add = new TrivialAddHandler<PermissionMapper>(PermissionMapper.class, attributes, PERMISSION_MAPPER_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<PermissionMapper> getValueSupplier(ServiceBuilder<PermissionMapper> serviceBuilder,
                    OperationContext context, ModelNode model) throws OperationFailedException {

                final InjectedValue<PermissionMapper> leftPermissionMapperInjector = new InjectedValue<>();
                final InjectedValue<PermissionMapper> rightPermissionMapperInjector = new InjectedValue<>();

                LogicalMapperOperation operation = LogicalMapperOperation.valueOf(LogicalMapperOperation.class, LOGICAL_OPERATION.resolveModelAttribute(context, model).asString().toUpperCase(Locale.ENGLISH));

                serviceBuilder.addDependency(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(PERMISSION_MAPPER_CAPABILITY, LEFT.resolveModelAttribute(context, model).asString()),
                        PermissionMapper.class), PermissionMapper.class, leftPermissionMapperInjector);

                serviceBuilder.addDependency(context.getCapabilityServiceName(RuntimeCapability.buildDynamicCapabilityName(PERMISSION_MAPPER_CAPABILITY, RIGHT.resolveModelAttribute(context, model).asString()),
                        PermissionMapper.class), PermissionMapper.class, rightPermissionMapperInjector);

                return () -> operation.create(leftPermissionMapperInjector.getValue(), rightPermissionMapperInjector.getValue());
            }
        };

        return new TrivialResourceDefinition(ElytronDescriptionConstants.LOGICAL_PERMISSION_MAPPER, add, attributes, PERMISSION_MAPPER_RUNTIME_CAPABILITY);
    }

    static ResourceDefinition getSimplePermissionMapper() {
        final AttributeDefinition[] attributes = new AttributeDefinition[] { MAPPING_MODE, PERMISSION_MAPPINGS };
        TrivialAddHandler<PermissionMapper>  add = new TrivialAddHandler<PermissionMapper>(PermissionMapper.class, attributes, PERMISSION_MAPPER_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<PermissionMapper> getValueSupplier(ServiceBuilder<PermissionMapper> serviceBuilder,
                    OperationContext context, ModelNode model) throws OperationFailedException {
                return () -> PermissionMapper.EMPTY_PERMISSION_MAPPER;
            }
        };

        return new TrivialResourceDefinition(ElytronDescriptionConstants.SIMPLE_PERMISSION_MAPPER, add, attributes, PERMISSION_MAPPER_RUNTIME_CAPABILITY);
    }

    private enum MappingMode {

        AND,

        OR,

        XOR,

        UNLESS,

        FIRST;

        SimplePermissionMapper.MappingMode convert() {
            switch (this) {
                case AND:
                    return SimplePermissionMapper.MappingMode.AND;
                case OR:
                    return SimplePermissionMapper.MappingMode.OR;
                case XOR:
                    return SimplePermissionMapper.MappingMode.XOR;
                case UNLESS:
                    return SimplePermissionMapper.MappingMode.UNLESS;
                default:
                    return SimplePermissionMapper.MappingMode.FIRST_MATCH;
            }
        }

    }

    private enum LogicalMapperOperation {

        AND((l,r) -> l.and(r)),

        OR((l,r) -> l.or(r)),

        XOR((l,r) -> l.xor(r)),

        UNLESS((l,r) -> l.unless(r));

        private final BinaryOperator<PermissionMapper> operator;

        private LogicalMapperOperation(BinaryOperator<PermissionMapper> operator) {
            this.operator = operator;
        }

        PermissionMapper create (PermissionMapper left, PermissionMapper right) {
            return operator.apply(left, right);
        }

    }
}
