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

import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;
import static org.wildfly.extension.elytron.RegexAttributeDefinitions.PATTERN;

import java.util.regex.Pattern;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractRemoveStepHandler;
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
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.auth.util.RegexNameValidatingRewriter;

/**
 * General container class for {@link NameRewriter}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class NameRewriterDefinitions {

    static final SimpleAttributeDefinition REPLACEMENT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REPLACEMENT, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition REPLACE_ALL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REPLACE_ALL, ModelType.BOOLEAN, true)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(false))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition MATCH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MATCH, ModelType.BOOLEAN, false)
        .setAllowExpression(true)
        .setDefaultValue(new ModelNode(true))
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    static final SimpleAttributeDefinition CONSTANT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CONSTANT, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
        .build();

    private static final AggregateComponentDefinition<NameRewriter> AGGREGATE_NAME_REWRITER = AggregateComponentDefinition.create(NameRewriter.class,
        ElytronDescriptionConstants.AGGREGATE_NAME_REWRITER, ElytronDescriptionConstants.NAME_REWRITERS, NAME_REWRITER_RUNTIME_CAPABILITY,
        (NameRewriter[] n) -> NameRewriter.chain(n));

    static AggregateComponentDefinition<NameRewriter> getAggregateNameRewriterDefinition() {
        return AGGREGATE_NAME_REWRITER;
    }

    static ResourceDefinition getRegexNameRewriterDefinition() {
        return new RegexNameRewriterDefinition();
    }

    static ResourceDefinition getRegexNameValidatingRewriterDefinition() {
        return new RegexNameValidatingRewriterDefinition();
    }

    static ResourceDefinition getConstantNameRewriterDefinition() {
        return new ConstantNameRewriterDefinition();
    }

    private static class RegexNameRewriterDefinition extends SimpleResourceDefinition {

        private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { PATTERN, REPLACEMENT, REPLACE_ALL };

        private static final AbstractAddStepHandler ADD = new NameRewriterAddHandler(ATTRIBUTES) {

            @Override
            protected ValueSupplier<NameRewriter> getNameRewriterSupplier(OperationContext context, ModelNode operation,
                ModelNode model) throws OperationFailedException {
                final Pattern pattern     = Pattern.compile(PATTERN.resolveModelAttribute(context, model).asString());
                final String  replacement = REPLACEMENT.resolveModelAttribute(context, model).asString();
                final boolean replaceAll  = REPLACE_ALL.resolveModelAttribute(context, model).asBoolean();

                return () -> new RegexNameRewriter(pattern, replacement, replaceAll);
            }
        };

        private static final AbstractRemoveStepHandler REMOVE = new NameRewriterRemoveHandler(ADD);

        private RegexNameRewriterDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.REGEX_NAME_REWRITER), ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.REGEX_NAME_REWRITER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            OperationStepHandler write = new WriteAttributeHandler(ElytronDescriptionConstants.REGEX_NAME_REWRITER, ATTRIBUTES);
            for (AttributeDefinition current : ATTRIBUTES) {
                resourceRegistration.registerReadWriteAttribute(current, null, write);
            }
        }
    }

    private static class RegexNameValidatingRewriterDefinition extends SimpleResourceDefinition {

        private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[] { PATTERN, MATCH };

        private static final AbstractAddStepHandler ADD = new NameRewriterAddHandler(ATTRIBUTES) {

            @Override
            protected ValueSupplier<NameRewriter> getNameRewriterSupplier(OperationContext context, ModelNode operation,
                    ModelNode model) throws OperationFailedException {
                final Pattern pattern = Pattern.compile(PATTERN.resolveModelAttribute(context, model).asString());
                final boolean match = MATCH.resolveModelAttribute(context, model).asBoolean();

                return () -> new RegexNameValidatingRewriter(pattern, match);
            }

        };

        private static final AbstractRemoveStepHandler REMOVE = new NameRewriterRemoveHandler(ADD);

        private RegexNameValidatingRewriterDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.REGEX_NAME_VALIDATING_REWRITER),
                    ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.REGEX_NAME_VALIDATING_REWRITER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
            OperationStepHandler write = new WriteAttributeHandler(ElytronDescriptionConstants.REGEX_NAME_VALIDATING_REWRITER, ATTRIBUTES);
            for (AttributeDefinition current : ATTRIBUTES) {
                resourceRegistration.registerReadWriteAttribute(current, null, write);
            }
        }

    }

    private static class ConstantNameRewriterDefinition extends SimpleResourceDefinition {

        private static final AbstractAddStepHandler ADD = new NameRewriterAddHandler(new AttributeDefinition[] { CONSTANT }) {

            @Override
            protected ValueSupplier<NameRewriter> getNameRewriterSupplier(OperationContext context, ModelNode operation,
                    ModelNode model) throws OperationFailedException {
                final String constant = CONSTANT.resolveModelAttribute(context, model).asString();
                return () -> NameRewriter.constant(constant);
            }

        };

        private static final AbstractRemoveStepHandler REMOVE = new NameRewriterRemoveHandler(ADD);

        private ConstantNameRewriterDefinition() {
            super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.CONSTANT_NAME_REWRITER),
                    ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.CONSTANT_NAME_REWRITER))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES));
        }

        @Override
        public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
                resourceRegistration.registerReadWriteAttribute(CONSTANT, null, new WriteAttributeHandler(ElytronDescriptionConstants.CONSTANT_NAME_REWRITER, CONSTANT) );
        }

    }

    private abstract static class NameRewriterAddHandler extends AbstractAddStepHandler {

        private NameRewriterAddHandler(final AttributeDefinition[] attributes) {
            super(NAME_REWRITER_RUNTIME_CAPABILITY, attributes);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();
            RuntimeCapability<Void> runtimeCapability = NAME_REWRITER_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
            ServiceName realmName = runtimeCapability.getCapabilityServiceName(NameRewriter.class);

            TrivialService<NameRewriter> nameRewriterService = new TrivialService<NameRewriter>(getNameRewriterSupplier(context, operation, model));

            commonDependencies(serviceTarget.addService(realmName, nameRewriterService))
                .setInitialMode(Mode.ACTIVE)
                .install();
        }

        protected abstract ValueSupplier<NameRewriter> getNameRewriterSupplier(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException;

    }

    private static class NameRewriterRemoveHandler extends ServiceRemoveStepHandler {

        public NameRewriterRemoveHandler(AbstractAddStepHandler addOperation) {
            super(addOperation, NAME_REWRITER_RUNTIME_CAPABILITY);
        }

        @Override
        protected ServiceName serviceName(String name) {
            return NAME_REWRITER_RUNTIME_CAPABILITY.fromBaseCapability(name).getCapabilityServiceName(NameRewriter.class);
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler(String parentName, AttributeDefinition ... attributes) {
            super(parentName, attributes);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress pathAddress) {
            return NAME_REWRITER_RUNTIME_CAPABILITY.fromBaseCapability(pathAddress.getLastElement().getValue()).getCapabilityServiceName(NameRewriter.class);
        }
    }

}
