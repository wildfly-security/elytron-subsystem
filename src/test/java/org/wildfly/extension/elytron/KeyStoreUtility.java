/*
 * JBoss, Home of Professional Open Source
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.io.File;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.jboss.as.controller.security.CredentialStoreURIParser;
import org.jboss.logging.Logger;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.impl.KeystorePasswordStore;

/**
 * KeyStoreUtility is a utility class that can handle dynamic KeyStore creation and manipulation.
 * It can also clean up files it created.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class KeyStoreUtility {

    private static Logger LOGGER = Logger.getLogger(KeyStoreUtility.class);

    public static final String DEFAULT_KEYSTORE_FILE = "test.keystore";

    private final String keyStoreType;
    private final String keyStore;
    private final String keyStorePassword;
    private String credentialStoreFile;
    private final Provider provider;

    private static String FILE_SEPARATOR = System.getProperty("file.separator");
    private static String TMP_DIR = System.getProperty("java.io.tmpdir");
    private static String DEFAULT_PASSWORD = "super_secret";

    private CredentialStore credentialStore;

    /**
     * Create keystore with all required files. It is the most complete constructor.
     * If keyStore doesn't exist it will be created with specified keyStoreType and
     * encryption directory will be created if not existent.
     *
     * @param keyStore
     * @param keyStorePassword
     * @param keyStoreType - JCEKS, JKS or null
     */
    public KeyStoreUtility(String keyStore, String keyStorePassword, String keyStoreType, Provider provider) {
        this.provider = provider;
        if (keyStoreType == null) {
            this.keyStoreType = "JCEKS";
        } else {
            if (!keyStoreType.equals("JCEKS") && !keyStoreType.equals("JKS")) {
                throw new IllegalArgumentException("Wrong keyStoreType. Supported are only (JCEKS or JKS). Preferred is JCEKS.");
            }
            this.keyStoreType = keyStoreType;
        }

        if (keyStorePassword == null) {
            this.keyStorePassword = DEFAULT_PASSWORD;
        } else if (keyStorePassword.startsWith(PicketBoxSecurityVault.PASS_MASK_PREFIX)) {
            throw new IllegalArgumentException("keyStorePassword cannot be a masked password, use plain text password, please");
        } else {
            this.keyStorePassword = keyStorePassword;
        }

        try {
            File keyStoreFile = new File(keyStore);
            if (!keyStoreFile.exists()) {
                if (!this.keyStoreType.equals("JCEKS")) {
                    throw new RuntimeException("keyStoreType has to be JCEKS when creating new key store");
                }
                File keyStoreParent = keyStoreFile.getAbsoluteFile().getParentFile();
                if (keyStoreParent != null) {
                    if (!keyStoreParent.exists()) {
                        assert keyStoreParent.mkdirs();
                    } else {
                        assert keyStoreParent.isDirectory();
                    }
                }
                createKeyStore(this.keyStoreType, this.keyStorePassword.toCharArray());
            }
            this.keyStore = keyStoreFile.getAbsolutePath();
        } catch (Exception e) {
            throw new RuntimeException("Problem creating keyStore: ", e);
        }


        if (LOGGER.isDebugEnabled()) {
            logCreatedVault();
        }

    }

    public static KeyStore createKeyStore(String keyStoreType, char[] keyStorePWD) throws Exception {
        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load((InputStream)null, keyStorePWD);
        return ks;
    }

    public CredentialStore createCredentialStore(String uri, String type, String provider) {
        CredentialStoreURIParser vaultURIParser = null;
        Map<String, String> credentialStoreAttributes;
        if (uri != null) {
            try {
                vaultURIParser = new CredentialStoreURIParser(uri);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            String name = vaultURIParser.getName(); // once we specify name, the name from uri is ignored
            credentialStoreAttributes = vaultURIParser.getOptionsMap();
            credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_NAME, name);
            String storageFile = vaultURIParser.getStorageFile();
            if (storageFile != null) {
                credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_FILE, storageFile);
                credentialStoreFile = storageFile;
            }
        } else {
            credentialStoreAttributes = new HashMap<>();
            credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_NAME, new File(keyStore).getName());
            credentialStoreAttributes.put(ElytronDescriptionConstants.CREDENTIAL_STORE_FILE, keyStore);
        }

        try {
            credentialStore = provider != null ? CredentialStore.getInstance(type, provider) : CredentialStore.getInstance(type);
            credentialStore.initialize(credentialStoreAttributes);
            return credentialStore;
        } catch (CredentialStoreException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public CredentialStore createCredentialStore(String type) {
        return createCredentialStore(null, type, null);
    }

    public CredentialStore createCredentialStore() {
        return createCredentialStore(null, KeystorePasswordStore.KEY_STORE_PASSWORD_STORE, null);
    }

    /**
     * Delete associated files.
     */
    public void cleanUp() {
        deleteIfExists(new File(keyStore));
        if (credentialStoreFile != null)
            deleteIfExists(new File(credentialStoreFile));
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public String getCredentialStoreFile() {
        return credentialStoreFile;
    }

    private void logCreatedVault() {
        LOGGER.debug("keystore="+keyStore);
        LOGGER.debug("KEYSTORE_PASSWORD="+keyStorePassword);
    }

    private static void deleteIfExists(File f) {
        assert !f.exists() || f.delete();
    }

}
