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
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedElement;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.DEFAULT_REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.POST_REALM_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.PRE_REALM_NAME_REWRITER;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALM;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.REALMS;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SECURITY_DOMAIN;
import static org.wildfly.extension.elytron.ElytronSubsystemParser.verifyNamespace;

import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 * A parser for the security realm definition.
 *
 * <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DomainParser {

    void readDomain(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations)
            throws XMLStreamException {
        ModelNode addDomain = new ModelNode();
        addDomain.get(OP).set(ADD);

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
                    case PRE_REALM_NAME_REWRITER:
                        DomainDefinition.PRE_REALM_NAME_REWRITER.parseAndSetParameter(value, addDomain, reader);
                        break;
                    case POST_REALM_NAME_REWRITER:
                        DomainDefinition.POST_REALM_NAME_REWRITER.parseAndSetParameter(value, addDomain, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (name == null) {
            throw missingRequired(reader, NAME);
        }

        addDomain.get(OP_ADDR).set(parentAddress).add(SECURITY_DOMAIN, name);

        String defaultRealm = null;

        while (reader.hasNext() && reader.nextTag() != END_ELEMENT) {
            verifyNamespace(reader);
            String localName = reader.getLocalName();
            if (REALM.equals(localName) == false) {
                throw unexpectedElement(reader);
            }

            String realmName = parseRealmElement(addDomain, reader);
            if (defaultRealm == null) {
                defaultRealm = realmName;
            }
        }

        if (defaultRealm == null) {
            throw missingRequired(reader, REALM);
        }
        DomainDefinition.DEFAULT_REALM.parseAndSetParameter(defaultRealm, addDomain, reader);
        operations.add(addDomain);
    }

    private String parseRealmElement(ModelNode addOperation, XMLExtendedStreamReader reader) throws XMLStreamException {

        String realmName = null;

        ModelNode realm = new ModelNode();

        final int count = reader.getAttributeCount();
        for (int i = 0; i < count; i++) {
            final String attributeValue = reader.getAttributeValue(i);
            if (!isNoNamespaceAttribute(reader, i)) {
                throw unexpectedAttribute(reader, i);
            } else {
                String attribute = reader.getAttributeLocalName(i);
                switch (attribute) {
                    case NAME:
                        realmName = attributeValue;
                        DomainDefinition.REALM_NAME.parseAndSetParameter(attributeValue, realm, reader);
                        break;
                    case NAME_REWRITER:
                        DomainDefinition.REALM_NAME_REWRITER.parseAndSetParameter(attributeValue, realm, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (realmName == null) {
            throw missingRequired(reader, NAME);
        }

        requireNoContent(reader);

        addOperation.get(REALMS).add(realm);
        return realmName;
    }

    void writeDomain(String name, ModelNode domain, XMLExtendedStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(SECURITY_DOMAIN);
        writer.writeAttribute(NAME, name);
        DomainDefinition.PRE_REALM_NAME_REWRITER.marshallAsAttribute(domain, writer);
        DomainDefinition.POST_REALM_NAME_REWRITER.marshallAsAttribute(domain, writer);

        String defaultRealm = domain.require(DEFAULT_REALM).asString();
        List<ModelNode> realms = domain.get(REALMS).asList();

        // Yeah not right - but ready for a complex attribute debate.

        for (ModelNode current : realms) {
            if (defaultRealm.equals(current.asString())) {
                writeRealm(current, writer);
                break;
            }
        }

        for (ModelNode current : realms) {
            if (defaultRealm.equals(current.asString()) == false) {
                writeRealm(current, writer);
            }
        }

        writer.writeEndElement();
    }

    private void writeRealm(ModelNode realm, XMLExtendedStreamWriter writer) throws XMLStreamException {
        writer.writeStartElement(REALM);
        DomainDefinition.REALM_NAME.marshallAsAttribute(realm, writer);
        DomainDefinition.REALM_NAME_REWRITER.marshallAsAttribute(realm, writer);
        writer.writeEndElement();
    }

}

