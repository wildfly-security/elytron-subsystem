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
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.JAAS_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.CONFIGURATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALMS;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.dmr.ModelNode;
import org.jboss.dmr.Property;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

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
                case JAAS_REALM:
                    readJaasRealm(parentAddress, reader, operations);
                    break;
                case KEYSTORE_REALM:
                    readKeyStoreRealm(parentAddress, reader, operations);
                    break;
                default:
                    throw unexpectedElement(reader);
            }
        }
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

    private void startRealms(boolean started, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (started == false) {
            writer.writeStartElement(REALMS);
        }
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

    void writeRealms(ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        boolean realmsStarted = false;

        realmsStarted = realmsStarted | writeJaasRealms(realmsStarted, subsystem, writer);
        realmsStarted = realmsStarted | writeKeyStoreRealms(realmsStarted, subsystem, writer);

        if (realmsStarted) {
            writer.writeEndElement();
        }
    }

}
