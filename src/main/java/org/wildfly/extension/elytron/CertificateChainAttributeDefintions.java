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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.wildfly.security.sasl.util.HexConverter;

/**
 * Class to contain the attribute definitions for certificates and their chains.
 *
 * Also contains utility methods to convert from the {@link Certificate} to the {@link ModelNode} representation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CertificateChainAttributeDefintions {

    private static final String SHA_1 = "SHA-1";

    private static final String SHA_256 = "SHA-256";

    private static final SimpleAttributeDefinition TYPE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.TYPE, ModelType.STRING).build();

    private static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ALGORITHM, ModelType.STRING).build();

    private static final SimpleAttributeDefinition ENCODED = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ENCODED, ModelType.STRING).build();

    private static final SimpleAttributeDefinition FORMAT = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FORMAT, ModelType.STRING).build();

    private static final ObjectTypeAttributeDefinition PUBLIC_KEY = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.PUBLIC_KEY, ALGORITHM, FORMAT, ENCODED).build();

    private static final SimpleAttributeDefinition VALUE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.VALUE, ModelType.STRING).build();

    private static final ObjectTypeAttributeDefinition FINGER_PRINT = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.FINGER_PRINT, ALGORITHM, VALUE).build();

    // Should this me a map so we don't need to specify the algorithm?
    private static final ObjectListAttributeDefinition FINGER_PRINTS = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.FINGER_PRINTS, FINGER_PRINT).build();

    private static final ObjectTypeAttributeDefinition CERTIFICATE = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.CERTIFICATE, TYPE, PUBLIC_KEY, FINGER_PRINTS, ENCODED).build();

    static final ObjectListAttributeDefinition CERTIFICATES = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.CERTIFICATES, CERTIFICATE)
        .setStorageRuntime()
        .setAllowNull(false)
        .build();

    /**
     * Populate the supplied response with the model representation of the certificate chain.
     *
     * @param result the response to populate.
     * @param certificateChain the certificate chain to add to the response.
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    static void writeAttribute(final ModelNode result, final Certificate[] certificateChain) throws CertificateEncodingException, NoSuchAlgorithmException {
        for (Certificate current : certificateChain) {
            ModelNode certificate = new ModelNode();
            certificate.get(ElytronDescriptionConstants.TYPE).set(current.getType());

            PublicKey publicKey = current.getPublicKey();
            ModelNode publicKeyModel = new ModelNode();
            publicKeyModel.get(ElytronDescriptionConstants.ALGORITHM).set(publicKey.getAlgorithm());
            publicKeyModel.get(ElytronDescriptionConstants.FORMAT).set(publicKey.getFormat());
            publicKeyModel.get(ElytronDescriptionConstants.ENCODED).set(encodedHexString(publicKey.getEncoded()));
            certificate.get(ElytronDescriptionConstants.PUBLIC_KEY).set(publicKeyModel);

            ModelNode fingerPrintsModel = new ModelNode();
            byte[] encodedCertificate = current.getEncoded();

            ModelNode sha1 = new ModelNode();
            sha1.get(ElytronDescriptionConstants.ALGORITHM).set(SHA_1);
            sha1.get(ElytronDescriptionConstants.VALUE).set(encodedHexString(digest(SHA_1, encodedCertificate)));
            fingerPrintsModel.add(sha1);

            ModelNode sha256 = new ModelNode();
            sha256.get(ElytronDescriptionConstants.ALGORITHM).set(SHA_256);
            sha256.get(ElytronDescriptionConstants.VALUE).set(encodedHexString(digest(SHA_256, encodedCertificate)));
            fingerPrintsModel.add(sha256);

            certificate.get(ElytronDescriptionConstants.FINGER_PRINTS).set(fingerPrintsModel);

            certificate.get(ElytronDescriptionConstants.ENCODED).set(encodedHexString(encodedCertificate));
            result.add(certificate);
        }
    }

    private static byte[] digest(final String algorithm, final byte[] encoded) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);

        return digest.digest(encoded);
    }

    private static String encodedHexString(byte[] encoded) {
        StringBuilder sb = new StringBuilder();
        char[] hexChars = HexConverter.convertToHexString(encoded).toCharArray();

        for (int i = 0; i < hexChars.length; i++) {
            sb.append(hexChars[i]);
            if (i + 1 < hexChars.length && (i + 1) % 2 == 0) {
                sb.append(':');
            }
        }

        return sb.toString();
    }

}
