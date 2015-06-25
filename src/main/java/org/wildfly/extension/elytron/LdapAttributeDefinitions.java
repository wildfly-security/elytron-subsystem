/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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

import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;

/**
 * The attribute definitions used by the {@link org.jboss.as.domain.management.security.LdapResourceDefinition}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class LdapAttributeDefinitions {

    static class PrincipalMappingAttributes {

        static final SimpleAttributeDefinition USE_X500_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_X500_NAME, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition NAME_ATTRIBUTE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.NAME_ATTRIBUTE, ModelType.STRING, true)
                .setAllowExpression(true)
                .setAlternatives(ElytronDescriptionConstants.USE_X500_NAME)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition USE_X500_PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_X500_PRINCIPAL, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition CACHE_PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CACHE_PRINCIPAL, ModelType.BOOLEAN, false)
                .setDefaultValue(new ModelNode(false))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition USE_RECURSIVE_SEARCH = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.USE_RECURSIVE_SEARCH, ModelType.BOOLEAN, false)
                .setRequires(ElytronDescriptionConstants.SEARCH_BASE_DN)
                .setDefaultValue(new ModelNode(true))
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition SEARCH_BASE_DN = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SEARCH_BASE_DN, ModelType.STRING, true)
                .setRequires(ElytronDescriptionConstants.NAME_ATTRIBUTE)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {USE_X500_NAME, NAME_ATTRIBUTE, USE_X500_PRINCIPAL, CACHE_PRINCIPAL, USE_RECURSIVE_SEARCH, SEARCH_BASE_DN};

        static final ObjectTypeAttributeDefinition PRINCIPAL_MAPPING = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.PRINCIPAL_MAPPING, ATTRIBUTES)
                .setAllowNull(false)
                .build();
    }

    static class DirContextAttributes {

        static final SimpleAttributeDefinition URL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.URL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition AUTHENTICATION_LEVEL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AUTHENTICATION_LEVEL, ModelType.STRING, false)
                .setDefaultValue(new ModelNode("simple"))
                .setAllowedValues("none", "simple", "strong")
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition PRINCIPAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition CREDENTIAL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREDENTIAL, ModelType.STRING, false)
                .setAllowExpression(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        static final SimpleAttributeDefinition[] ATTRIBUTES = new SimpleAttributeDefinition[] {URL, AUTHENTICATION_LEVEL, PRINCIPAL, CREDENTIAL};

        static final ObjectTypeAttributeDefinition DIR_CONTEXT = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.DIR_CONTEXT, ATTRIBUTES)
                .setAllowNull(false)
                .build();
    }

}
