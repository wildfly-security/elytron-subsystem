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

import static org.wildfly.extension.elytron._private.ElytronSubsystemMessages.ROOT_LOGGER;
import static org.wildfly.extension.elytron.CertificateChainAttributeDefintions.CERTIFICATES;
import static org.wildfly.extension.elytron.CertificateChainAttributeDefintions.writeAttribute;
import static org.wildfly.extension.elytron.KeyStoreAliasDefinition.alias;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.dmr.ModelNode;
import org.wildfly.extension.elytron.KeyStoreDefinition.ReadAttributeHandler;

/**
 * A {@link ResourceDefinition} for {@link X509Certificate} representations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class X509CertificateChainDefinition extends SimpleResourceDefinition {

    X509CertificateChainDefinition() {
        super(PathElement.pathElement(ElytronDescriptionConstants.CERTIFICATE_CHAIN, ElytronDescriptionConstants.X509),
            ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.KEYSTORE, ElytronDescriptionConstants.ALIAS,
                    ElytronDescriptionConstants.CERTIFICATE_CHAIN, ElytronDescriptionConstants.X509));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        resourceRegistration.registerReadOnlyAttribute(CERTIFICATES, new ReadAttributeHandler() {

            @Override
            protected void populateResult(ModelNode result, ModelNode operation, KeyStoreService keyStoreService) throws OperationFailedException {
                String alias = alias(operation);
                KeyStore  keyStore = keyStoreService.getValue();

                try {
                    writeAttribute(result, keyStore.getCertificateChain(alias));
                } catch (KeyStoreException | IllegalStateException | IllegalArgumentException | CertificateEncodingException | NoSuchAlgorithmException e) {
                    throw ROOT_LOGGER.unableToPopulateResult(e);
                }
            }
        });
    }

}
