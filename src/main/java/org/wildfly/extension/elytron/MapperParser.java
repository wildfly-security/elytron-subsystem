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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AGGREGATE_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DELEGATE_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FROM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAPPED_REGEX_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MAPPERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.MATCH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITERS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PATTERN;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM_MAP;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REGEX_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REGEX_NAME_VALIDATING_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REPLACEMENT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REPLACE_ALL;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SIMPLE_REGEX_REALM_MAPPER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.TO;
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
import org.jboss.dmr.Property;
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
                case CUSTOM_NAME_REWRITER:
                    readCustomComponent(CUSTOM_NAME_REWRITER, parentAddress, reader, operations);
                    break;
                case REGEX_NAME_REWRITER:
                    readRegexNameRewriterElement(parentAddress, reader, operations);
                    break;
                case REGEX_NAME_VALIDATING_REWRITER:
                    readRegexNameValidatingRewriterElement(parentAddress, reader, operations);
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

    private void startMappers(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(MAPPERS);
        }
    }

    private boolean writeAggregateNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_NAME_REWRITER)) {
            startMappers(started, writer);
            List<Property> nameRewriters = subsystem.require(AGGREGATE_NAME_REWRITER).asPropertyList();
            for (Property current : nameRewriters) {
                ModelNode nameRewriter = current.getValue();
                writer.writeStartElement(AGGREGATE_NAME_REWRITER);
                writer.writeAttribute(NAME, current.getName());

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
            List<Property> realms = subsystem.require(CUSTOM_NAME_REWRITER).asPropertyList();
            for (Property current : realms) {
                ModelNode realm = current.getValue();

                writeCustomComponent(CUSTOM_NAME_REWRITER, current.getName(), realm, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeRegexNameRewriters(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(REGEX_NAME_REWRITER)) {
            startMappers(started, writer);
            List<Property> nameRewriters = subsystem.require(REGEX_NAME_REWRITER).asPropertyList();
            for (Property current : nameRewriters) {
                ModelNode nameRewriter = current.getValue();
                writer.writeStartElement(REGEX_NAME_REWRITER);
                writer.writeAttribute(NAME, current.getName());
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
            List<Property> nameRewriters = subsystem.require(REGEX_NAME_VALIDATING_REWRITER).asPropertyList();
            for (Property current : nameRewriters) {
                ModelNode nameRewriter = current.getValue();
                writer.writeStartElement(REGEX_NAME_VALIDATING_REWRITER);
                writer.writeAttribute(NAME, current.getName());
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(nameRewriter, writer);
                NameRewriterDefinitions.MATCH.marshallAsAttribute(nameRewriter, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomRealmMapper(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_REALM_MAPPER)) {
            startMappers(started, writer);
            List<Property> realmMappers = subsystem.require(CUSTOM_REALM_MAPPER).asPropertyList();
            for (Property current : realmMappers) {
                ModelNode realmMapper = current.getValue();

                writeCustomComponent(CUSTOM_REALM_MAPPER, current.getName(), realmMapper, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeSimpleRegexRealmMapper(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(SIMPLE_REGEX_REALM_MAPPER)) {
            startMappers(started, writer);
            List<Property> nameRewriters = subsystem.require(SIMPLE_REGEX_REALM_MAPPER).asPropertyList();
            for (Property current : nameRewriters) {
                ModelNode realmMapper = current.getValue();
                writer.writeStartElement(SIMPLE_REGEX_REALM_MAPPER);
                writer.writeAttribute(NAME, current.getName());
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.DELEGATE_REALM_MAPPER.marshallAsAttribute(realmMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeMapRegexRealmMapper(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(MAPPED_REGEX_REALM_MAPPER)) {
            startMappers(started, writer);
            List<Property> nameRewriters = subsystem.require(MAPPED_REGEX_REALM_MAPPER).asPropertyList();
            for (Property current : nameRewriters) {
                ModelNode realmMapper = current.getValue();
                writer.writeStartElement(MAPPED_REGEX_REALM_MAPPER);
                writer.writeAttribute(NAME, current.getName());
                RegexAttributeDefinitions.PATTERN.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.DELEGATE_REALM_MAPPER.marshallAsAttribute(realmMapper, writer);
                RealmMapperDefinitions.REALM_REALM_MAP.marshallAsElement(realmMapper, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    void writeMappers(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        boolean mappersStarted = false;

        mappersStarted = mappersStarted | writeAggregateNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeCustomNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeRegexNameRewriters(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeRegexNameValidatingRewriters(mappersStarted, subsystem, writer);

        mappersStarted = mappersStarted | writeCustomRealmMapper(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeSimpleRegexRealmMapper(mappersStarted, subsystem, writer);
        mappersStarted = mappersStarted | writeMapRegexRealmMapper(mappersStarted, subsystem, writer);

        if (mappersStarted) {
            writer.writeEndElement();
        }
    }
}
