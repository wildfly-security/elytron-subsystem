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

import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.isNoNamespaceAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequired;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequiredElement;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AGGREGATE_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ATTRIBUTE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.ATTRIBUTE_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHENTICATION_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHORIZATION_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONFIGURATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DIR_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FILE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.FILESYSTEM_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.GROUPS_PROPERTIES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JAAS_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JDBC_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LDAP_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LEVELS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PATH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PLAIN_TEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_QUERY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROPERTIES_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.RELATIVE_TO;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SECURITY_REALMS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.USERS_PROPERTIES;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.readCustomComponent;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.writeCustomComponent;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;
import org.wildfly.extension.elytron.JdbcRealmDefinition.PasswordMapperObjectDefinition;
import org.wildfly.extension.elytron.JdbcRealmDefinition.PrincipalQueryAttributes;
import org.wildfly.extension.elytron.LdapRealmDefinition.DirContextObjectDefinition;
import org.wildfly.extension.elytron.LdapRealmDefinition.PrincipalMappingObjectDefinition;

/**
 * A parser for the security realm definition.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RealmParser {

    void readRealms(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        requireNoAttributes(reader);
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            switch (localName) {
                case AGGREGATE_REALM:
                    readAggregateRealm(parentAddress, reader, operations);
                    break;
                case CUSTOM_REALM:
                    readCustomComponent(CUSTOM_REALM, parentAddress, reader, operations);
                    break;
                case JAAS_REALM:
                    readJaasRealm(parentAddress, reader, operations);
                    break;
                case JDBC_REALM:
                    readJdbcRealm(parentAddress, reader, operations);
                    break;
                case KEYSTORE_REALM:
                    readKeyStoreRealm(parentAddress, reader, operations);
                    break;
                case PROPERTIES_REALM:
                    readPropertiesRealm(parentAddress, reader, operations);
                    break;
                case LDAP_REALM:
                    readLdapRealm(parentAddress, reader, operations);
                    break;
                case FILESYSTEM_REALM:
                    readFileSystemRealm(parentAddress, reader, operations);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
    }

    private void readAggregateRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, AUTHENTICATION_REALM, AUTHORIZATION_REALM }));
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
                    case AUTHENTICATION_REALM:
                        AggregateRealmDefinition.AUTHENTICATION_REALM.parseAndSetParameter(value, addRealm, reader);
                        break;
                    case AUTHORIZATION_REALM:
                        AggregateRealmDefinition.AUTHORIZATION_REALM.parseAndSetParameter(value, addRealm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addRealm.get(OP_ADDR).set(parentAddress).add(AGGREGATE_REALM, name);

        requireNoContent(reader);

        operations.add(addRealm);
    }

    private void readJaasRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

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
                    case CONFIGURATION:
                        JaasRealmDefinition.CONFIGURATION.parseAndSetParameter(value, addRealm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addRealm.get(OP_ADDR).set(parentAddress).add(JAAS_REALM, name);

        operations.add(addRealm);

        requireNoContent(reader);
    }

    private void readJdbcRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

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

        addRealm.get(OP_ADDR).set(parentAddress).add(JDBC_REALM, name);

        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            switch (localName) {
                case PRINCIPAL_QUERY:
                    ModelNode principalQueryNode = readModelNode(PrincipalQueryAttributes.ATTRIBUTES, reader, (parentNode, reader1) -> {
                        if (reader1.getLocalName().equals(ATTRIBUTE_MAPPING)) {
                            ModelNode attributeMappingNode = readModelNode(null, reader, (parentNode1, reader2) -> {
                                if (reader2.getLocalName().equals(ATTRIBUTE)) {
                                    parentNode1.add(readModelNode(JdbcRealmDefinition.AttributeMappingObjectDefinition.ATTRIBUTES, reader2, null));
                                    requireNoContent(reader2);
                                } else {
                                    throw unexpectedElement(reader2);
                                }
                            });
                            parentNode.get(ATTRIBUTE_MAPPING).set(attributeMappingNode);
                        } else if (PrincipalQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.containsKey(reader1.getLocalName())) {
                            PasswordMapperObjectDefinition passwordMapperObjectDefinition = PrincipalQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.get(reader1.getLocalName());

                            ModelNode passwordMapperNode = readModelNode(passwordMapperObjectDefinition.getAttributes(), reader1, null);

                            parentNode.get(reader1.getLocalName()).set(passwordMapperNode);

                            requireNoContent(reader1);
                        } else {
                            throw unexpectedElement(reader1);
                        }
                    });

                    addRealm.get(PRINCIPAL_QUERY).add(principalQueryNode);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }

        if (!addRealm.hasDefined(PRINCIPAL_QUERY)) {
            throw missingRequiredElement(reader, Collections.singleton(PRINCIPAL_QUERY));
        }

        operations.add(addRealm);
    }

    private void readKeyStoreRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, KEYSTORE }));
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
                    case KEYSTORE:
                        KeyStoreRealmDefinition.KEYSTORE.parseAndSetParameter(value, addRealm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addRealm.get(OP_ADDR).set(parentAddress).add(KEYSTORE_REALM, name);

        operations.add(addRealm);

        requireNoContent(reader);
    }

    private void readPropertiesRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

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
                    case PLAIN_TEXT:
                        PropertiesRealmDefinition.PLAIN_TEXT.parseAndSetParameter(value, addRealm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }
        addRealm.get(OP_ADDR).set(parentAddress).add(PROPERTIES_REALM, name);

        boolean usersPropertiesFound = false;
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            switch (localName) {
                case USERS_PROPERTIES:
                    ModelNode usersProperties = new ModelNode();
                    readFileAttributes(usersProperties, reader);
                    addRealm.get(USERS_PROPERTIES).set(usersProperties);
                    usersPropertiesFound = true;
                    break;
                case GROUPS_PROPERTIES:
                    ModelNode groupsProperties = new ModelNode();
                    readFileAttributes(groupsProperties, reader);
                    addRealm.get(GROUPS_PROPERTIES).set(groupsProperties);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }

        if (usersPropertiesFound == false) {
            throw missingRequiredElement(reader, Collections.singleton(USERS_PROPERTIES));
        }

        operations.add(addRealm);
    }

    private void readFileSystemRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);


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
                    case LEVELS:
                        FileSystemRealmDefinition.LEVELS.parseAndSetParameter(value, addRealm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, Collections.singleton(NAME));
        }

        addRealm.get(OP_ADDR).set(parentAddress).add(FILESYSTEM_REALM, name);

        operations.add(addRealm);

        boolean hasFile = false;
        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            switch (localName) {
                case FILE:
                    readFileAttributes(addRealm, reader);
                    hasFile = true;
                    break;
                case NAME_REWRITER:
                    readNameRewriterReference(addRealm, reader);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
        if (!hasFile) {
            throw missingRequiredElement(reader, Collections.singleton(FILE));
        }
    }

    private void readNameRewriterReference(ModelNode addRealm, XMLExtendedStreamReader reader) throws XMLStreamException {
        boolean found = false;
        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        FileSystemRealmDefinition.NAME_REWRITER.parseAndSetParameter(value, addRealm, reader);
                        found = true;
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (!found) {
            throw missingRequired(reader, NAME);
        }

        requireNoContent(reader);
    }


    private void readFileAttributes(ModelNode file, XMLExtendedStreamReader reader) throws XMLStreamException {
        boolean pathFound = false;
        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case PATH:
                        FileAttributeDefinitions.PATH.parseAndSetParameter(value, file, reader);
                        pathFound = true;
                        break;
                    case RELATIVE_TO:
                        FileAttributeDefinitions.RELATIVE_TO.parseAndSetParameter(value, file, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (pathFound == false) {
            throw missingRequired(reader, PATH);
        }

        requireNoContent(reader);
    }

    private void readLdapRealm(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);

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

        addRealm.get(OP_ADDR).set(parentAddress).add(LDAP_REALM, name);

        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();

            switch (localName) {
                case DIR_CONTEXT:
                    ModelNode dirContextNode = readModelNode(DirContextObjectDefinition.ATTRIBUTES, reader, null);
                    requireNoContent(reader);
                    addRealm.get(DIR_CONTEXT).set(dirContextNode);
                    break;
                case PRINCIPAL_MAPPING:
                    ModelNode principalMappingNode = readModelNode(PrincipalMappingObjectDefinition.ATTRIBUTES, reader, (parentNode, reader1) -> {
                        if (reader1.getLocalName().equals(ATTRIBUTE_MAPPING)) {
                            ModelNode attributeMappingNode = readModelNode(null, reader, (parentNode1, reader2) -> {
                                if (reader1.getLocalName().equals(ATTRIBUTE)) {
                                    parentNode1.add(readModelNode(LdapRealmDefinition.AttributeMappingObjectDefinition.ATTRIBUTES, reader1, null));
                                    requireNoContent(reader1);
                                } else {
                                    throw unexpectedElement(reader1);
                                }
                            });

                            parentNode.get(ATTRIBUTE_MAPPING).set(attributeMappingNode);
                        } else {
                            throw unexpectedElement(reader1);
                        }
                    });

                    addRealm.get(PRINCIPAL_MAPPING).set(principalMappingNode);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }

        operations.add(addRealm);
    }

    private ModelNode readModelNode(AttributeDefinition[] attributes, XMLExtendedStreamReader reader, ChildModelNodeReader childReader) throws XMLStreamException {
        ModelNode newModelNode = new ModelNode();
        final int count = reader.getAttributeCount();

        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                AttributeDefinition attributeDefinition = null;

                for (AttributeDefinition current : attributes) {
                    if (attribute.equals(current.getName())) {
                        attributeDefinition = current;
                        break;
                    }
                }

                if (attributeDefinition == null) {
                    throw unexpectedAttribute(reader, i);
                }

                if (SimpleAttributeDefinition.class.isInstance(attributeDefinition)) {
                    SimpleAttributeDefinition simpleAttributeDefinition = (SimpleAttributeDefinition) attributeDefinition;
                    simpleAttributeDefinition.parseAndSetParameter(value, newModelNode, reader);
                }
            }
        }

        if (childReader != null) {
            while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
                verifyNamespace(reader);
                childReader.read(newModelNode, reader);
            }
        }

        return newModelNode;
    }

    private void startRealms(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(SECURITY_REALMS);
        }
    }

    private boolean writeAggregateRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_REALM)) {
            startRealms(started, writer);
            ModelNode realms = subsystem.require(AGGREGATE_REALM);
            for (String name : realms.keys()) {
                ModelNode realm = realms.require(name);
                writer.writeStartElement(AGGREGATE_REALM);
                writer.writeAttribute(NAME, name);
                AggregateRealmDefinition.AUTHENTICATION_REALM.marshallAsAttribute(realm, writer);
                AggregateRealmDefinition.AUTHORIZATION_REALM.marshallAsAttribute(realm, writer);
                writer.writeEndElement();
            }

            return true;
        }

        return false;
    }

    private boolean writeCustomRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(CUSTOM_REALM)) {
            startRealms(started, writer);
            ModelNode realms = subsystem.require(CUSTOM_REALM);
            for (String name : realms.keys()) {
                ModelNode realm = realms.require(name);

                writeCustomComponent(CUSTOM_REALM, name, realm, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeJaasRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(JAAS_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(JAAS_REALM);
            for (String name : realms.keys()) {
                writer.writeStartElement(JAAS_REALM);
                writer.writeAttribute(NAME, name);
                JaasRealmDefinition.CONFIGURATION.marshallAsAttribute(realms.require(name), writer);
                writer.writeEndElement();
            }
            return true;
        }
        return false;
    }

    private boolean writeJdbcRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(JDBC_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(JDBC_REALM);

            for (String name : realms.keys()) {
                writer.writeStartElement(JDBC_REALM);
                writer.writeAttribute(NAME, name);
                ModelNode jdbcRealmNode = realms.require(name);

                for (ModelNode principalQueryNode : jdbcRealmNode.get(PRINCIPAL_QUERY).asList()) {
                    writeObjectTypeAttribute(PRINCIPAL_QUERY, PrincipalQueryAttributes.ATTRIBUTES, principalQueryNode, writer, new ChildModelNodeWriter() {
                        @Override
                        public void write(ModelNode modelNode, XMLExtendedStreamWriter writer) throws XMLStreamException {
                            for (PasswordMapperObjectDefinition mapperDefinition : PrincipalQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.values()) {
                                ObjectTypeAttributeDefinition objectDefinition = mapperDefinition.getObjectDefinition();

                                writeObjectTypeAttribute(objectDefinition.getName(), mapperDefinition.getAttributes(), modelNode.get(objectDefinition.getName()), writer, null);
                            }

                            ModelNode attributeMappingNode = modelNode.get(ATTRIBUTE_MAPPING);

                            if (attributeMappingNode.isDefined()) {
                                writer.writeStartElement(ATTRIBUTE_MAPPING);

                                for (ModelNode elementNode : attributeMappingNode.asList()) {
                                    writeObjectTypeAttribute(ATTRIBUTE, JdbcRealmDefinition.AttributeMappingObjectDefinition.ATTRIBUTES, elementNode, writer, null);
                                }

                                writer.writeEndElement();
                            }
                        }
                    });
                }

                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private boolean writeKeyStoreRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(KEYSTORE_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(KEYSTORE_REALM);
            for (String name : realms.keys()) {
                writer.writeStartElement(KEYSTORE_REALM);
                writer.writeAttribute(NAME, name);
                KeyStoreRealmDefinition.KEYSTORE.marshallAsAttribute(realms.require(name), writer);
                writer.writeEndElement();
            }
            return true;
        }
        return false;
    }

    private boolean writePropertiesRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(PROPERTIES_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(PROPERTIES_REALM);
            for (String name : realms.keys()) {
                writer.writeStartElement(PROPERTIES_REALM);
                writer.writeAttribute(NAME, name);
                ModelNode model = realms.require(name);
                PropertiesRealmDefinition.PLAIN_TEXT.marshallAsAttribute(model, writer);
                writeFile(USERS_PROPERTIES, model.get(USERS_PROPERTIES), writer);
                writeFile(GROUPS_PROPERTIES, model.get(GROUPS_PROPERTIES), writer);
                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private void writeFile(String elementName, ModelNode fileAttribute, XMLExtendedStreamWriter writer)
            throws XMLStreamException {
        if (fileAttribute.isDefined()) {
            writer.writeStartElement(elementName);
            FileAttributeDefinitions.PATH.marshallAsAttribute(fileAttribute, writer);
            FileAttributeDefinitions.RELATIVE_TO.marshallAsAttribute(fileAttribute, writer);
            writer.writeEndElement();
        }
    }

    private boolean writeLdapRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(LDAP_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(LDAP_REALM);

            for (String name : realms.keys()) {
                writer.writeStartElement(LDAP_REALM);
                writer.writeAttribute(NAME, name);
                ModelNode ldapRealmNode = realms.require(name);

                writeObjectTypeAttribute(DIR_CONTEXT, DirContextObjectDefinition.ATTRIBUTES, ldapRealmNode.get(DIR_CONTEXT), writer, null);
                writeObjectTypeAttribute(PRINCIPAL_MAPPING, PrincipalMappingObjectDefinition.ATTRIBUTES, ldapRealmNode.get(PRINCIPAL_MAPPING), writer, (modelNode, writer1) -> {
                    ModelNode attributeMappingNode = modelNode.get(ATTRIBUTE_MAPPING);

                    if (attributeMappingNode.isDefined()) {
                        writer1.writeStartElement(ATTRIBUTE_MAPPING);

                        for (ModelNode elementNode : attributeMappingNode.asList()) {
                            writeObjectTypeAttribute(ATTRIBUTE, LdapRealmDefinition.AttributeMappingObjectDefinition.ATTRIBUTES, elementNode, writer1, null);
                        }

                        writer1.writeEndElement();
                    }
                });

                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private boolean writeFileSystemRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(FILESYSTEM_REALM)) {
            startRealms(started, writer);

            ModelNode realms = subsystem.require(FILESYSTEM_REALM);

            for (String name : realms.keys()) {
                final ModelNode model = realms.require(name);
                writer.writeStartElement(FILESYSTEM_REALM);
                writer.writeAttribute(NAME, name);
                FileSystemRealmDefinition.LEVELS.marshallAsAttribute(model, writer);

                writer.writeStartElement(FILE);
                FileSystemRealmDefinition.PATH.marshallAsAttribute(model, writer);
                FileSystemRealmDefinition.RELATIVE_TO.marshallAsAttribute(model, writer);
                writer.writeEndElement();

                if (model.hasDefined(NAME_REWRITER)) {
                    writer.writeStartElement(NAME_REWRITER);
                    FileSystemRealmDefinition.NAME_REWRITER.marshallAsAttribute(model, writer);
                    writer.writeEndElement();
                }

                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private void writeObjectTypeAttribute(String name, AttributeDefinition[] attributes, ModelNode attributeNode, XMLExtendedStreamWriter writer, ChildModelNodeWriter childModelNodeWriter)
            throws XMLStreamException {
        if (attributeNode.isDefined()) {
            writer.writeStartElement(name);

            for (AttributeDefinition attributeDefinition : attributes) {
                if (SimpleAttributeDefinition.class.isInstance(attributeDefinition)) {
                    ((SimpleAttributeDefinition) attributeDefinition).marshallAsAttribute(attributeNode, writer);
                }
            }

            if (childModelNodeWriter != null) {
                childModelNodeWriter.write(attributeNode, writer);
            }

            writer.writeEndElement();
        }
    }

    void writeRealms(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        boolean realmsStarted = false;

        realmsStarted = realmsStarted | writeAggregateRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeCustomRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeJaasRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeJdbcRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeKeyStoreRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writePropertiesRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeLdapRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeFileSystemRealms(realmsStarted, subsystem, writer);

        if (realmsStarted) {
            writer.writeEndElement();
        }
    }

    private interface ChildModelNodeReader {
        void read(ModelNode parentNode, XMLExtendedStreamReader reader) throws XMLStreamException;
    }

    private interface ChildModelNodeWriter {
        void write(ModelNode modelNode, XMLExtendedStreamWriter writer) throws XMLStreamException;
    }
}
