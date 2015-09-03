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

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.isNoNamespaceAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequired;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequiredElement;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.requireSingleAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ADD_PREFIX_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ADD_SUFFIX_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AGGREGATE_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AGGREGATE_PRINCIPAL_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AGGREGATE_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ATTRIBUTE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CHAINED_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONSTANT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONSTANT_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONSTANT_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_PERMISSION_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_PRINCIPAL_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_ROLE_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DELEGATE_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.EMPTY_ROLE_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FROM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JOINER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LEFT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LOGICAL_OPERATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LOGICAL_ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAPPED_REGEX_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAPPERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MATCH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAXIMUM_SEGMENTS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.OID;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PATTERN;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PREFIX;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_DECODERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM_MAP;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REGEX_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REGEX_NAME_VALIDATING_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REPLACEMENT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REPLACE_ALL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.RIGHT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ROLES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ROLE_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ROLE_MAPPERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SIMPLE_REGEX_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SIMPLE_ROLE_DECODER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SUFFIX;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TO;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.X500_ATTRIBUTE_PRINCIPAL_DECODER;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.readCustomComponent;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.writeCustomComponent;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.as.controller.ListAttributeDefinition;
import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * XML handling for the <mappers /> element.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class MapperParser {

    void readMappers(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            switch (localName) {
                // Name Rewriters
                case AGGREGATE_NAME_REWRITER:
                    readAggregateNameRewriterElement(parentAddress, reader, operations);
                    break;
                case CHAINED_NAME_REWRITER:
                    readChainedNameRewriterElement(parentAddress, reader, operations);
                    break;
                case CONSTANT_NAME_REWRITER:
                    readConstantRewriterElement(parentAddress, reader, operations);
                    break;
                case CUSTOM_NAME_REWRITER:
                    readCustomComponent(CUSTOM_NAME_REWRITER, parentAddress, reader, operations);
                    break;
                case REGEX_NAME_REWRITER:
                    readRegexNameRewriterElement(parentAddress, reader, operations);
                    break;
                case REGEX_NAME_VALIDATING_REWRITER:
                    readRegexNameValidatingRewriterElement(parentAddress, reader, operations);
                    break;
                // Permission Mapper
                case CUSTOM_PERMISSION_MAPPER:
                    readCustomComponent(CUSTOM_PERMISSION_MAPPER, parentAddress, reader, operations);
                    break;
                // Principal Decoders
                case AGGREGATE_PRINCIPAL_DECODER:
                    readAggregatePrincipalDecoderElement(parentAddress, reader, operations);
                    break;
                case CUSTOM_PRINCIPAL_DECODER:
                    readCustomComponent(CUSTOM_PRINCIPAL_DECODER, parentAddress, reader, operations);
                    break;
                case X500_ATTRIBUTE_PRINCIPAL_DECODER:
                    readX500AttributePrincipalDecoderElement(parentAddress, reader, operations);
                    break;
                // Realm Mappers
                case CUSTOM_REALM_MAPPER:
                    readCustomComponent(CUSTOM_REALM_MAPPER, parentAddress, reader, operations);
                    break;
                case SIMPLE_REGEX_REALM_MAPPER:
                    readSimpleRegexRealmMapperElement(parentAddress, reader, operations);
                    break;
                case MAPPED_REGEX_REALM_MAPPER:
                    readMappedRegexRealmMapperElement(parentAddress, reader, operations);
                    break;
                // Role Decoders
                case CUSTOM_ROLE_DECODER:
                    readCustomComponent(CUSTOM_ROLE_DECODER, parentAddress, reader, operations);
                    break;
                case EMPTY_ROLE_DECODER:
                    readEmptyRoleDecoder(parentAddress, reader, operations);
                    break;
                case SIMPLE_ROLE_DECODER:
                    readSimpleRoleDecoder(parentAddress, reader, operations);
                    break;
                // Role Mappers
                case ADD_PREFIX_ROLE_MAPPER:
                    readAddPrefixRoleMapper(parentAddress, reader, operations);
                    break;
                case ADD_SUFFIX_ROLE_MAPPER:
                    readAddSuffixRoleMapper(parentAddress, reader, operations);
                    break;
                case AGGREGATE_ROLE_MAPPER:
                    readAggregateRoleMapperElement(parentAddress, reader, operations);
                    break;
                case CONSTANT_ROLE_MAPPER:
                    readConstantRoleMapper(parentAddress, reader, operations);
                    break;
                case CUSTOM_ROLE_MAPPER:
                    readCustomComponent(CUSTOM_ROLE_MAPPER, parentAddress, reader, operations);
                    break;
                case LOGICAL_ROLE_MAPPER:
                    readLogicalRoleMapper(parentAddress, reader, operations);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
    }

    private void readAggregateNameRewriterElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(AGGREGATE_NAME_REWRITER, name);

        operations.add(addNameRewriter);

        ListAttributeDefinition nameRewriters = NameRewriterDefinitions.getAggregateNameRewriterDefinition().getReferencesAttribute();
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (NAME_REWRITER.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            requireSingleAttribute(reader, NAME);
            String nameRewriterName = reader.getAttributeValue(0);


            nameRewriters.parseAndAddParameterElement(nameRewriterName, addNameRewriter, reader);

            requireNoContent(reader);
        }
    }

    private void readChainedNameRewriterElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(CHAINED_NAME_REWRITER, name);

        operations.add(addNameRewriter);

        ListAttributeDefinition nameRewriters = NameRewriterDefinitions.getAggregateNameRewriterDefinition().getReferencesAttribute();
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (NAME_REWRITER.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            requireSingleAttribute(reader, NAME);
            String nameRewriterName = reader.getAttributeValue(0);


            nameRewriters.parseAndAddParameterElement(nameRewriterName, addNameRewriter, reader);

            requireNoContent(reader);
        }
    }

    private void readConstantRewriterElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, CONSTANT }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case CONSTANT:
                        NameRewriterDefinitions.CONSTANT.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(CONSTANT_NAME_REWRITER, name);

        operations.add(addNameRewriter);

        requireNoContent(reader);
    }

    private void readRegexNameRewriterElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, PATTERN, REPLACEMENT }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case PATTERN:
                        RegexAttributeDefinitions.PATTERN.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    case REPLACEMENT:
                        NameRewriterDefinitions.REPLACEMENT.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    case REPLACE_ALL:
                        NameRewriterDefinitions.REPLACE_ALL.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(REGEX_NAME_REWRITER, name);

        operations.add(addNameRewriter);

        requireNoContent(reader);
    }

    private void readRegexNameValidatingRewriterElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, PATTERN }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case PATTERN:
                        RegexAttributeDefinitions.PATTERN.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    case MATCH:
                        NameRewriterDefinitions.MATCH.parseAndSetParameter(value, addNameRewriter, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(REGEX_NAME_VALIDATING_REWRITER, name);

        operations.add(addNameRewriter);

        requireNoContent(reader);
    }

    private void readAggregatePrincipalDecoderElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addNameRewriter = new ModelNode();
        addNameRewriter.get(OP).set(ADD);

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addNameRewriter.get(OP_ADDR).set(parentAddress).add(AGGREGATE_PRINCIPAL_DECODER, name);

        operations.add(addNameRewriter);

        ListAttributeDefinition principalDecoders = PrincipalDecoderDefinitions.getAggregatePrincipalDecoderDefinition().getReferencesAttribute();
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (PRINCIPAL_DECODER.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            requireSingleAttribute(reader, NAME);
            String principalDecoderName = reader.getAttributeValue(0);


            principalDecoders.parseAndAddParameterElement(principalDecoderName, addNameRewriter, reader);

            requireNoContent(reader);
        }
    }

    private void readX500AttributePrincipalDecoderElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addPrincipalDecoder = new ModelNode();
        addPrincipalDecoder.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, OID }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case OID:
                        PrincipalDecoderDefinitions.OID.parseAndSetParameter(value, addPrincipalDecoder, reader);
                        break;
                    case JOINER:
                        PrincipalDecoderDefinitions.JOINER.parseAndSetParameter(value, addPrincipalDecoder, reader);
                        break;
                    case MAXIMUM_SEGMENTS:
                        PrincipalDecoderDefinitions.MAXIMUM_SEGMENTS.parseAndSetParameter(value, addPrincipalDecoder, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addPrincipalDecoder.get(OP_ADDR).set(parentAddress).add(X500_ATTRIBUTE_PRINCIPAL_DECODER, name);

        operations.add(addPrincipalDecoder);

        requireNoContent(reader);
    }

    private void readSimpleRegexRealmMapperElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRealmMapper = new ModelNode();
        addRealmMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, PATTERN }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case PATTERN:
                        RegexAttributeDefinitions.PATTERN.parseAndSetParameter(value, addRealmMapper, reader);
                        break;
                    case DELEGATE_REALM_MAPPER:
                        RealmMapperDefinitions.DELEGATE_REALM_MAPPER.parseAndSetParameter(value, addRealmMapper, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addRealmMapper.get(OP_ADDR).set(parentAddress).add(SIMPLE_REGEX_REALM_MAPPER, name);

        operations.add(addRealmMapper);

        requireNoContent(reader);
    }

    private void readMappedRegexRealmMapperElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRealmMapper = new ModelNode();
        addRealmMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, PATTERN }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case PATTERN:
                        RegexAttributeDefinitions.PATTERN.parseAndSetParameter(value, addRealmMapper, reader);
                        break;
                    case DELEGATE_REALM_MAPPER:
                        RealmMapperDefinitions.DELEGATE_REALM_MAPPER.parseAndSetParameter(value, addRealmMapper, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addRealmMapper.get(OP_ADDR).set(parentAddress).add(MAPPED_REGEX_REALM_MAPPER, name);
        operations.add(addRealmMapper);

        ModelNode realmNameMap = addRealmMapper.get(REALM_MAP);

        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (REALM_MAPPING.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            readRealmMapping(realmNameMap, reader);
        }

        if (realmNameMap.isDefined() == false) {
            throw missingRequiredElement(reader, Collections.singleton(REALM_MAPPING));
        }

    }

    private void readRealmMapping(ModelNode realmNameMap, XMLExtendedStreamReader reader) throws XMLStreamException {
        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { FROM, TO }));

        String from = null;
        String to = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case FROM:
                        from = value;
                        break;
                    case TO:
                        to = value;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);
        realmNameMap.add(from, to);
    }

    private void readEmptyRoleDecoder(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        requireSingleAttribute(reader, NAME);
        String name = reader.getAttributeValue(0);

        requireNoContent(reader);

        ModelNode addRoleDecoder = new ModelNode();
        addRoleDecoder.get(OP).set(ADD);
        addRoleDecoder.get(OP_ADDR).set(parentAddress).add(EMPTY_ROLE_DECODER, name);
        operations.add(addRoleDecoder);
    }

    private void readSimpleRoleDecoder(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRoleDecoder = new ModelNode();
        addRoleDecoder.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, ATTRIBUTE }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case ATTRIBUTE:
                        RoleDecoderDefinitions.ATTRIBUTE.parseAndSetParameter(value, addRoleDecoder, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);

        addRoleDecoder.get(OP_ADDR).set(parentAddress).add(SIMPLE_ROLE_DECODER, name);
        operations.add(addRoleDecoder);
    }

    private void readAddPrefixRoleMapper(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRoleMapper = new ModelNode();
        addRoleMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, PREFIX }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case PREFIX:
                        RoleMapperDefinitions.PREFIX.parseAndSetParameter(value, addRoleMapper, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);

        addRoleMapper.get(OP_ADDR).set(parentAddress).add(ADD_PREFIX_ROLE_MAPPER, name);
        operations.add(addRoleMapper);
    }

    private void readAddSuffixRoleMapper(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRoleMapper = new ModelNode();
        addRoleMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, SUFFIX }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case SUFFIX:
                        RoleMapperDefinitions.SUFFIX.parseAndSetParameter(value, addRoleMapper, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);

        addRoleMapper.get(OP_ADDR).set(parentAddress).add(ADD_SUFFIX_ROLE_MAPPER, name);
        operations.add(addRoleMapper);
    }

    private void readAggregateRoleMapperElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRoleMapper = new ModelNode();
        addRoleMapper.get(OP).set(ADD);

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addRoleMapper.get(OP_ADDR).set(parentAddress).add(AGGREGATE_ROLE_MAPPER, name);

        operations.add(addRoleMapper);

        ListAttributeDefinition roleMappers = RoleMapperDefinitions.getAggregateRoleMapperDefinition().getReferencesAttribute();
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (ROLE_MAPPER.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            requireSingleAttribute(reader, NAME);
            String roleMapperName = reader.getAttributeValue(0);


            roleMappers.parseAndAddParameterElement(roleMapperName, addRoleMapper, reader);

            requireNoContent(reader);
        }
    }

    private void readConstantRoleMapper(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRoleMapper = new ModelNode();
        addRoleMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, ROLES }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case ROLES:
                        for (String role : reader.getListAttributeValue(i)) {
                            RoleMapperDefinitions.ROLES.parseAndAddParameterElement(role, addRoleMapper, reader);
                        }
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);

        addRoleMapper.get(OP_ADDR).set(parentAddress).add(CONSTANT_ROLE_MAPPER, name);
        operations.add(addRoleMapper);
    }

    private void readLogicalRoleMapper(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRoleMapper = new ModelNode();
        addRoleMapper.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, LOGICAL_OPERATION, LEFT, RIGHT }));

        String name = null;

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                requiredAttributes.remove(attribute);
                switch (attribute) {
                    case NAME:
                        name = value;
                        break;
                    case LOGICAL_OPERATION:
                        RoleMapperDefinitions.LOGICAL_OPERATION.parseAndSetParameter(value, addRoleMapper, reader);
                        break;
                    case LEFT:
                        RoleMapperDefinitions.LEFT.parseAndSetParameter(value, addRoleMapper, reader);
                        break;
                    case RIGHT:
                        RoleMapperDefinitions.RIGHT.parseAndSetParameter(value, addRoleMapper, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        requireNoContent(reader);

        addRoleMapper.get(OP_ADDR).set(parentAddress).add(LOGICAL_ROLE_MAPPER, name);
        operations.add(addRoleMapper);
    }

    private void startMappers(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(MAPPERS);
        }
    }

    private boolean writeAggregateNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_NAME_REWRITER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(AGGREGATE_NAME_REWRITER);
            for (String name : nameRewriters.keys()) {
                ModelNode nameRewriter = nameRewriters.require(name);
                writer.writeStartElement(AGGREGATE_NAME_REWRITER);
                writer.writeAttribute(NAME, name);

                List<ModelNode> nameRewriterReferences = nameRewriter.get(NAME_REWRITERS).asList();
                for (ModelNode currentReference : nameRewriterReferences) {
                    writer.writeStartElement(NAME_REWRITER);
                    writer.writeAttribute(NAME, currentReference.asString());
                    writer.writeEndElement();
                }

                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeChainedNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CHAINED_NAME_REWRITER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(CHAINED_NAME_REWRITER);
            for (String name : nameRewriters.keys()) {
                ModelNode nameRewriter = nameRewriters.require(name);
                writer.writeStartElement(CHAINED_NAME_REWRITER);
                writer.writeAttribute(NAME, name);

                List<ModelNode> nameRewriterReferences = nameRewriter.get(NAME_REWRITERS).asList();
                for (ModelNode currentReference : nameRewriterReferences) {
                    writer.writeStartElement(NAME_REWRITER);
                    writer.writeAttribute(NAME, currentReference.asString());
                    writer.writeEndElement();
                }

                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_NAME_REWRITER)) {
            startMappers(started, writer);
            ModelNode realms = subsystem.require(CUSTOM_NAME_REWRITER);
            for (String name : realms.keys()) {
                ModelNode realm = realms.require(name);

                writeCustomComponent(CUSTOM_NAME_REWRITER, name, realm, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeConstantNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CONSTANT_NAME_REWRITER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(CONSTANT_NAME_REWRITER);
            for (String name : nameRewriters.keys()) {
                ModelNode nameRewriter = nameRewriters.require(name);
                writer.writeStartElement(CONSTANT_NAME_REWRITER);
                writer.writeAttribute(NAME, name);
                NameRewriterDefinitions.CONSTANT.marshallAsAttribute(nameRewriter, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeRegexNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(REGEX_NAME_REWRITER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(REGEX_NAME_REWRITER);
            for (String name : nameRewriters.keys()) {
                ModelNode nameRewriter = nameRewriters.require(name);
                writer.writeStartElement(REGEX_NAME_REWRITER);
                writer.writeAttribute(NAME, name);
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(nameRewriter, writer);
                NameRewriterDefinitions.REPLACEMENT.marshallAsAttribute(nameRewriter, writer);
                NameRewriterDefinitions.REPLACE_ALL.marshallAsAttribute(nameRewriter, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeRegexNameValidatingRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(REGEX_NAME_VALIDATING_REWRITER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(REGEX_NAME_VALIDATING_REWRITER);
            for (String name : nameRewriters.keys()) {
                ModelNode nameRewriter = nameRewriters.require(name);
                writer.writeStartElement(REGEX_NAME_VALIDATING_REWRITER);
                writer.writeAttribute(NAME, name);
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(nameRewriter, writer);
                NameRewriterDefinitions.MATCH.marshallAsAttribute(nameRewriter, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomPermissionMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_PERMISSION_MAPPER)) {
            startMappers(started, writer);
            ModelNode principalDecoders = subsystem.require(CUSTOM_PERMISSION_MAPPER);
            for (String name : principalDecoders.keys()) {
                ModelNode principalDecoder = principalDecoders.require(name);

                writeCustomComponent(CUSTOM_PERMISSION_MAPPER, name, principalDecoder, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeAggregatePrincipalDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_PRINCIPAL_DECODER)) {
            startMappers(started, writer);
            ModelNode principalDecoders = subsystem.require(AGGREGATE_PRINCIPAL_DECODER);
            for (String name : principalDecoders.keys()) {
                ModelNode principalDecoder = principalDecoders.require(name);
                writer.writeStartElement(AGGREGATE_PRINCIPAL_DECODER);
                writer.writeAttribute(NAME, name);

                List<ModelNode> principalDecoderReferences = principalDecoder.get(PRINCIPAL_DECODERS).asList();
                for (ModelNode currentReference : principalDecoderReferences) {
                    writer.writeStartElement(PRINCIPAL_DECODER);
                    writer.writeAttribute(NAME, currentReference.asString());
                    writer.writeEndElement();
                }

                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomPrincipalDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_PRINCIPAL_DECODER)) {
            startMappers(started, writer);
            ModelNode principalDecoders = subsystem.require(CUSTOM_PRINCIPAL_DECODER);
            for (String name : principalDecoders.keys()) {
                ModelNode principalDecoder = principalDecoders.require(name);

                writeCustomComponent(CUSTOM_PRINCIPAL_DECODER, name, principalDecoder, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeX500AttributePrincipalDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(X500_ATTRIBUTE_PRINCIPAL_DECODER)) {
            startMappers(started, writer);
            ModelNode principalDecoders = subsystem.require(X500_ATTRIBUTE_PRINCIPAL_DECODER);
            for (String name : principalDecoders.keys()) {
                ModelNode principalDecoder = principalDecoders.require(name);
                writer.writeStartElement(X500_ATTRIBUTE_PRINCIPAL_DECODER);
                writer.writeAttribute(NAME, name);
                PrincipalDecoderDefinitions.OID.marshallAsAttribute(principalDecoder, writer);
                PrincipalDecoderDefinitions.JOINER.marshallAsAttribute(principalDecoder, writer);
                PrincipalDecoderDefinitions.MAXIMUM_SEGMENTS.marshallAsAttribute(principalDecoder, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomRealmMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_REALM_MAPPER)) {
            startMappers(started, writer);
            ModelNode realmMappers = subsystem.require(CUSTOM_REALM_MAPPER);
            for (String name : realmMappers.keys()) {
                ModelNode realmMapper = realmMappers.require(name);

                writeCustomComponent(CUSTOM_REALM_MAPPER, name, realmMapper, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeSimpleRegexRealmMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(SIMPLE_REGEX_REALM_MAPPER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(SIMPLE_REGEX_REALM_MAPPER);
            for (String name : nameRewriters.keys()) {
                ModelNode realmMapper = nameRewriters.require(name);
                writer.writeStartElement(SIMPLE_REGEX_REALM_MAPPER);
                writer.writeAttribute(NAME, name);
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.DELEGATE_REALM_MAPPER.marshallAsAttribute(realmMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeMapRegexRealmMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(MAPPED_REGEX_REALM_MAPPER)) {
            startMappers(started, writer);
            ModelNode nameRewriters = subsystem.require(MAPPED_REGEX_REALM_MAPPER);
            for (String name : nameRewriters.keys()) {
                ModelNode realmMapper = nameRewriters.require(name);
                writer.writeStartElement(MAPPED_REGEX_REALM_MAPPER);
                writer.writeAttribute(NAME, name);
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.DELEGATE_REALM_MAPPER.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.REALM_REALM_MAP.marshallAsElement(realmMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomRoleDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_ROLE_DECODER)) {
            startMappers(started, writer);
            ModelNode roleDecoders = subsystem.require(CUSTOM_ROLE_DECODER);
            for (String name : roleDecoders.keys()) {
                ModelNode roleDecoder = roleDecoders.require(name);

                writeCustomComponent(CUSTOM_ROLE_DECODER, name, roleDecoder, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeEmptyRoleDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(EMPTY_ROLE_DECODER)) {
            startMappers(started, writer);
            ModelNode roleDecoders = subsystem.require(EMPTY_ROLE_DECODER);
            for (String name : roleDecoders.keys()) {
                writer.writeStartElement(EMPTY_ROLE_DECODER);
                writer.writeAttribute(NAME, name);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeSimpleRoleDecoders(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(SIMPLE_ROLE_DECODER)) {
            startMappers(started, writer);
            ModelNode roleDecoders = subsystem.require(SIMPLE_ROLE_DECODER);
            for (String name : roleDecoders.keys()) {
                ModelNode roleDecoder = roleDecoders.require(name);
                writer.writeStartElement(SIMPLE_ROLE_DECODER);
                writer.writeAttribute(NAME, name);
                RoleDecoderDefinitions.ATTRIBUTE.marshallAsAttribute(roleDecoder, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeAddPrefixRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(ADD_PREFIX_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(ADD_PREFIX_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);
                writer.writeStartElement(ADD_PREFIX_ROLE_MAPPER);
                writer.writeAttribute(NAME, name);
                RoleMapperDefinitions.PREFIX.marshallAsAttribute(roleMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeAddSuffixRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(ADD_SUFFIX_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(ADD_SUFFIX_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);
                writer.writeStartElement(ADD_SUFFIX_ROLE_MAPPER);
                writer.writeAttribute(NAME, name);
                RoleMapperDefinitions.SUFFIX.marshallAsAttribute(roleMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeAggregateRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(AGGREGATE_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);
                writer.writeStartElement(AGGREGATE_ROLE_MAPPER);
                writer.writeAttribute(NAME, name);

                List<ModelNode> roleMapperReferences = roleMapper.get(ROLE_MAPPERS).asList();
                for (ModelNode currentReference : roleMapperReferences) {
                    writer.writeStartElement(ROLE_MAPPER);
                    writer.writeAttribute(NAME, currentReference.asString());
                    writer.writeEndElement();
                }

                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeConstantRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CONSTANT_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(CONSTANT_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);
                writer.writeStartElement(CONSTANT_ROLE_MAPPER);
                writer.writeAttribute(NAME, name);
                RoleMapperDefinitions.ROLES.getAttributeMarshaller().marshallAsAttribute(RoleMapperDefinitions.ROLES, roleMapper, false, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(CUSTOM_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);

                writeCustomComponent(CUSTOM_ROLE_MAPPER, name, roleMapper, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeLogicalRoleMappers(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(LOGICAL_ROLE_MAPPER)) {
            startMappers(started, writer);
            ModelNode roleMappers = subsystem.require(LOGICAL_ROLE_MAPPER);
            for (String name : roleMappers.keys()) {
                ModelNode roleMapper = roleMappers.require(name);
                writer.writeStartElement(LOGICAL_ROLE_MAPPER);
                writer.writeAttribute(NAME, name);
                RoleMapperDefinitions.LOGICAL_OPERATION.marshallAsAttribute(roleMapper, writer);
                RoleMapperDefinitions.LEFT.marshallAsAttribute(roleMapper, writer);
                RoleMapperDefinitions.RIGHT.marshallAsAttribute(roleMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    void writeMappers(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        boolean mappersStarted = false;

        mappersStarted = mappersStarted | writeAggregateNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeChainedNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeConstantNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeCustomNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeRegexNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeRegexNameValidatingRewriters(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeCustomPermissionMappers(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeAggregatePrincipalDecoders(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeCustomPrincipalDecoders(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeX500AttributePrincipalDecoders(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeCustomRealmMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeSimpleRegexRealmMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeMapRegexRealmMappers(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeCustomRoleDecoders(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeEmptyRoleDecoders(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeSimpleRoleDecoders(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeAddPrefixRoleMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeAddSuffixRoleMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeAggregateRoleMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeConstantRoleMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeCustomRoleMappers(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeLogicalRoleMappers(mappersStarted, subsystem, writer);


        if (mappersStarted) {
            writer.writeEndElement();
        }
    }
}
