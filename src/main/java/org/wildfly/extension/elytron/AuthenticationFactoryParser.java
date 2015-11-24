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

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.parsing.ParseUtils.isNoNamespaceAttribute;
import static org.jboss.as.controller.parsing.ParseUtils.missingRequired;
import static org.jboss.as.controller.parsing.ParseUtils.requireNoContent;
import static org.jboss.as.controller.parsing.ParseUtils.unexpectedAttribute;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.HTTP_SERVER_AUTHENITCATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.HTTP_SERVER_FACTORY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.NAME;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SASL_SERVER_AUTHENTICATION;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SASL_SERVER_FACTORY;
import static org.wildfly.extension.elytron.ElytronDescriptionConstants.SECURITY_DOMAIN;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.stream.XMLStreamException;

import org.jboss.dmr.ModelNode;
import org.jboss.staxmapper.XMLExtendedStreamReader;
import org.jboss.staxmapper.XMLExtendedStreamWriter;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AuthenticationFactoryParser {

    void readHttpServerAuthenticationElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addOperation = new ModelNode();
        addOperation.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, SECURITY_DOMAIN, HTTP_SERVER_FACTORY }));

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
                    case HTTP_SERVER_FACTORY:
                        AuthenticationFactoryDefinitions.HTTP_SERVER_FACTORY.parseAndSetParameter(value, addOperation, reader);
                        break;
                    case SECURITY_DOMAIN:
                        AuthenticationFactoryDefinitions.BASE_SECURITY_DOMAIN_REF.parseAndSetParameter(value, addOperation, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addOperation.get(OP_ADDR).set(parentAddress).add(HTTP_SERVER_AUTHENITCATION, name);

        operations.add(addOperation);

        requireNoContent(reader);

        System.out.println(addOperation);
    }

    void readSaslServerAuthenticationElement(ModelNode parentAddress, XMLExtendedStreamReader reader, List<ModelNode> operations) throws XMLStreamException {
        ModelNode addOperation = new ModelNode();
        addOperation.get(OP).set(ADD);

        Set<String> requiredAttributes = new HashSet<String>(Arrays.asList(new String[] { NAME, SECURITY_DOMAIN, SASL_SERVER_FACTORY }));

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
                    case SASL_SERVER_FACTORY:
                        SaslServerDefinitions.SASL_SERVER_FACTORY.parseAndSetParameter(value, addOperation, reader);
                        break;
                    case SECURITY_DOMAIN:
                        SaslServerDefinitions.SECURITY_DOMAIN.parseAndSetParameter(value, addOperation, reader);
                        break;
                    default:
                        throw unexpectedAttribute(reader, i);
                }
            }
        }

        if (requiredAttributes.isEmpty() == false) {
            throw missingRequired(reader, requiredAttributes);
        }

        addOperation.get(OP_ADDR).set(parentAddress).add(SASL_SERVER_AUTHENTICATION, name);

        operations.add(addOperation);

        requireNoContent(reader);
    }

    boolean writeHttpServerAuthentication(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer, WrapperWriter wrapperWriter) throws XMLStreamException {
        if (subsystem.hasDefined(HTTP_SERVER_AUTHENITCATION)) {
            wrapperWriter.start(started);
            ModelNode securityDomainHttpConfiguration = subsystem.require(HTTP_SERVER_AUTHENITCATION);
            for (String name : securityDomainHttpConfiguration.keys()) {
                ModelNode configuration = securityDomainHttpConfiguration.require(name);
                writer.writeStartElement(HTTP_SERVER_AUTHENITCATION);
                writer.writeAttribute(NAME, name);
                AuthenticationFactoryDefinitions.HTTP_SERVER_FACTORY.marshallAsAttribute(configuration, writer);
                AuthenticationFactoryDefinitions.BASE_SECURITY_DOMAIN_REF.marshallAsAttribute(configuration, writer);
                writer.writeEndElement();
            }
            return true;
        }

        return false;
    }

    boolean writeSaslServerAuthenticationonfiguration(boolean started, ModelNode subsystem, XMLExtendedStreamWriter writer, WrapperWriter wrapperWriter) throws XMLStreamException {
        if (subsystem.hasDefined(SASL_SERVER_AUTHENTICATION)) {
            wrapperWriter.start(started);
            ModelNode securityDomainSaslConfigurationInstances = subsystem.require(SASL_SERVER_AUTHENTICATION);
            for (String name : securityDomainSaslConfigurationInstances.keys()) {
                ModelNode securityDomainSaslConfiguration = securityDomainSaslConfigurationInstances.require(name);
                writer.writeStartElement(SASL_SERVER_AUTHENTICATION);
                writer.writeAttribute(NAME, name);
                SaslServerDefinitions.SASL_SERVER_FACTORY.marshallAsAttribute(securityDomainSaslConfiguration, writer);
                SaslServerDefinitions.SECURITY_DOMAIN.marshallAsAttribute(securityDomainSaslConfiguration, writer);
                writer.writeEndElement();
            }
            return true;
        }

        return false;
    }

    @FunctionalInterface
    interface WrapperWriter {

        void start(boolean started) throws XMLStreamException;

    }

}
