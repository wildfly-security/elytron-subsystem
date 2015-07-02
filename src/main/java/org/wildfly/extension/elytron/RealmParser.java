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
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHENTICATION_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHORIZATION_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.AUTHENTICATION_QUERY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONFIGURATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CUSTOM_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DIR_CONTEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.GROUPS_PROPERTIES;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JAAS_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JDBC_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.LDAP_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PATH;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PLAIN_TEXT;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRINCIPAL_MAPPING;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PROPERTIES_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALMS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.RELATIVE_TO;
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

import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.Property;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;
import org.wildfly.extension.elytron.JdbcRealmDefinition.AuthenticationQueryAttributes;
import org.wildfly.extension.elytron.JdbcRealmDefinition.PasswordMapperObjectDefinition;
import org.wildfly.extension.elytron.LdapAttributeDefinitions.DirContextAttributes;
import org.wildfly.extension.elytron.LdapAttributeDefinitions.PrincipalMappingAttributes;

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
                case AUTHENTICATION_QUERY:
                    ModelNode authenticationQueryNode = readAttributes(AuthenticationQueryAttributes.ATTRIBUTES, reader);

                    while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
                        verifyNamespace(reader);

                        String passwordMapperName = reader.getLocalName();

                        if (!AuthenticationQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.containsKey(passwordMapperName)) {
                            unexpectedElement(reader);
                        }

                        PasswordMapperObjectDefinition passwordMapperObjectDefinition = AuthenticationQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.get(passwordMapperName);

                        ModelNode passwordMapperNode = readAttributes(passwordMapperObjectDefinition.getAttributes(), reader);

                        authenticationQueryNode.get(passwordMapperName).set(passwordMapperNode);

                        requireNoContent(reader);
                    }

                    addRealm.get(AUTHENTICATION_QUERY).set(authenticationQueryNode);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }

        if (!addRealm.hasDefined(AUTHENTICATION_QUERY)) {
            throw missingRequiredElement(reader, Collections.singleton(AUTHENTICATION_QUERY));
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
                    ModelNode dirContextNode = readAttributes(DirContextAttributes.ATTRIBUTES, reader);
                    requireNoContent(reader);
                    addRealm.get(DIR_CONTEXT).set(dirContextNode);
                    break;
                case PRINCIPAL_MAPPING:
                    ModelNode principalMappingNode = readAttributes(PrincipalMappingAttributes.ATTRIBUTES, reader);
                    requireNoContent(reader);
                    addRealm.get(PRINCIPAL_MAPPING).set(principalMappingNode);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }

        operations.add(addRealm);
    }

    private ModelNode readAttributes(SimpleAttributeDefinition[] attributes, XMLExtendedStreamReader reader) throws XMLStreamException {
        ModelNode newPrincipalMappingModelNode = new ModelNode();

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String value = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                SimpleAttributeDefinition attributeDefinition = null;

                for (SimpleAttributeDefinition current : attributes) {
                    if (attribute.equals(current.getName())) {
                        attributeDefinition = current;
                        break;
                    }
                }

                if (attributeDefinition == null) {
                    throw unexpectedAttribute(reader, i);
                }

                attributeDefinition.parseAndSetParameter(value, newPrincipalMappingModelNode, reader);
            }
        }

        return newPrincipalMappingModelNode;
    }

    private void startRealms(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(REALMS);
        }
    }

    private boolean writeAggregateRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(AGGREGATE_REALM)) {
            startRealms(started, writer);
            List<Property> realms = subsystem.require(AGGREGATE_REALM).asPropertyList();
            for (Property current : realms) {
                ModelNode realm = current.getValue();
                writer.writeStartElement(AGGREGATE_REALM);
                writer.writeAttribute(NAME, current.getName());
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
            List<Property> realms = subsystem.require(CUSTOM_REALM).asPropertyList();
            for (Property current : realms) {
                ModelNode realm = current.getValue();

                writeCustomComponent(CUSTOM_REALM, current.getName(), realm, writer);
            }

            return true;
        }

        return false;
    }

    private boolean writeJaasRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(JAAS_REALM)) {
            startRealms(started, writer);

            List<Property> realms = subsystem.require(JAAS_REALM).asPropertyList();
            for (Property current : realms) {
                writer.writeStartElement(JAAS_REALM);
                writer.writeAttribute(NAME, current.getName());
                JaasRealmDefinition.CONFIGURATION.marshallAsAttribute(current.getValue(), writer);
                writer.writeEndElement();
            }
            return true;
        }
        return false;
    }

    private boolean writeJdbcRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(JDBC_REALM)) {
            startRealms(started, writer);

            List<Property> realms = subsystem.require(JDBC_REALM).asPropertyList();
            for (Property current : realms) {
                writer.writeStartElement(JDBC_REALM);

                writer.writeAttribute(NAME, current.getName());

                ModelNode jdbcRealmNode = current.getValue();

                writeAuthenticationQuery(jdbcRealmNode.get(AUTHENTICATION_QUERY), writer);

                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private void writeAuthenticationQuery(ModelNode authenticationQueryNode, XMLExtendedStreamWriter writer)
            throws XMLStreamException {
        if (authenticationQueryNode.isDefined()) {
            writer.writeStartElement(AUTHENTICATION_QUERY);

            for (SimpleAttributeDefinition attributeDefinition : AuthenticationQueryAttributes.ATTRIBUTES) {
                attributeDefinition.marshallAsAttribute(authenticationQueryNode, writer);
            }

            for (PasswordMapperObjectDefinition mapperDefinition : AuthenticationQueryAttributes.SUPPORTED_PASSWORD_MAPPERS.values()) {
                writePasswordMapper(mapperDefinition.getResourceDefinition(), authenticationQueryNode, writer);
            }

            writer.writeEndElement();
        }
    }

    private void writePasswordMapper(ObjectTypeAttributeDefinition attributeDefinition, ModelNode authenticationQueryNode, XMLExtendedStreamWriter writer)
            throws XMLStreamException {
        String name = attributeDefinition.getName();
        ModelNode modelNode = authenticationQueryNode.get(name);

        if (modelNode.isDefined()) {
            writer.writeStartElement(name);

            for (Property current : modelNode.asPropertyList()) {
                writer.writeAttribute(current.getName(), current.getValue().asString());
            }

            writer.writeEndElement();
        }
    }

    private boolean writeKeyStoreRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(KEYSTORE_REALM)) {
            startRealms(started, writer);

            List<Property> realms = subsystem.require(KEYSTORE_REALM).asPropertyList();
            for (Property current : realms) {
                writer.writeStartElement(KEYSTORE_REALM);
                writer.writeAttribute(NAME, current.getName());
                KeyStoreRealmDefinition.KEYSTORE.marshallAsAttribute(current.getValue(), writer);
                writer.writeEndElement();
            }
            return true;
        }
        return false;
    }

    private boolean writePropertiesRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(PROPERTIES_REALM)) {
            startRealms(started, writer);

            List<Property> realms = subsystem.require(PROPERTIES_REALM).asPropertyList();
            for (Property current : realms) {
                writer.writeStartElement(PROPERTIES_REALM);
                writer.writeAttribute(NAME, current.getName());
                ModelNode model = current.getValue();
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

            List<Property> realms = subsystem.require(LDAP_REALM).asPropertyList();

            for (Property current : realms) {
                writer.writeStartElement(LDAP_REALM);
                writer.writeAttribute(NAME, current.getName());

                writeLdapObjectTypeAttribute(DIR_CONTEXT, DirContextAttributes.ATTRIBUTES, current.getValue(), writer);
                writeLdapObjectTypeAttribute(PRINCIPAL_MAPPING, PrincipalMappingAttributes.ATTRIBUTES, current.getValue(), writer);

                writer.writeEndElement();
            }

            return true;
        }
        return false;
    }

    private void writeLdapObjectTypeAttribute(String name, SimpleAttributeDefinition[] attributes, ModelNode ldapRealmNode, XMLExtendedStreamWriter writer)
            throws XMLStreamException {
        ModelNode attributeNode = ldapRealmNode.get(name);
        writer.writeStartElement(name);

        for (SimpleAttributeDefinition attributeDefinition : attributes) {
            attributeDefinition.marshallAsAttribute(attributeNode, writer);
        }

        writer.writeEndElement();
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

        if (realmsStarted) {
            writer.writeEndElement();
        }
    }

}
