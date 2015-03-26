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
import static org.jboss.as.controller.parsing.ParseUtils.requireNoAttributes;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.requireSingleAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.KEYSTORE_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALMS;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

import java.util.List;

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
            if (REALM.equals(localName)) {
                readElement(parentAddress, reader, operations);
            } else {
                throw unexpectedElement(reader);
            }
        }
    }

    void readElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        requireSingleAttribute(reader, NAME);
        String realmName = reader.getAttributeValue(0);

        ModelNode addRealm = new ModelNode();
        addRealm.get(OP).set(ADD);
        addRealm.get(OP_ADDR).set(parentAddress).add(REALM, realmName);
        operations.add(addRealm);

        requireNoContent(reader);
    }

    private void startRealms(XMLExtendedStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(REALMS);
    }

    private boolean writeKeyStoreRealms(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer) throws XMLStreamException {
        if (subsystem.hasDefined(KEYSTORE_REALM)) {
            if (started == false) {
                startRealms(writer);
            }
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

        realmsStarted = realmsStarted & writeKeyStoreRealms(realmsStarted, subsystem, writer);

        if (realmsStarted) {
            writer.writeEndElement();
        }
    }

    void writeRealm(String name, ModelNode realm, XMLExtendedStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(REALM);
        writer.writeAttribute(NAME, name);
        writer.writeEndElement();
    }

}
