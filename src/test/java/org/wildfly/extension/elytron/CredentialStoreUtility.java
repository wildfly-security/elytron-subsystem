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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.jboss.logging.Logger;
import org.wildfly.common.Assert;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeystorePasswordStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * CredentialStoreUtility is a utility class that can handle dynamic CredentialStore creation, manipulation and deletion/removal of keystore file.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class CredentialStoreUtility {

    private static Logger LOGGER = Logger.getLogger(CredentialStoreUtility.class);

    private final String credentialStoreFileName;
    private final CredentialStore credentialStore;
    private static final String DEFAULT_PASSWORD = "super_secret";


    public static final String CRYPTO_ALGORITHM = "AES";
    public static final String ADMIN_KEY_ALIAS = "TEST_ADMIN_KEY_ALIAS";
    public static final int ADMIN_KEY_SIZE = 128;

    /**
     * Create Credential Store.
     *
     * @param credentialStoreFileName name of file to hold credentials
     * @param storePassword master password (clear text) to open the credential store
     * @param adminKeyPassword a password (clear text) for protecting admin key
     * @param createStorageFirst flag whether to create storage first and then initialize Credential Store
     */
    public CredentialStoreUtility(String credentialStoreFileName, String storePassword, String adminKeyPassword, boolean createStorageFirst) {
        Assert.checkNotNullParam("credentialStoreFileName", credentialStoreFileName);
        Assert.checkNotNullParam("storePassword", storePassword);
        Assert.checkNotNullParam("adminKeyPassword", adminKeyPassword);
        this.credentialStoreFileName = credentialStoreFileName;

        try {
            Map<String, String> attributes = new HashMap<>();
            if (createStorageFirst) {
                createKeyStore(storePassword.toCharArray(), adminKeyPassword.toCharArray());
                attributes.put(KeystorePasswordStore.KEY_ALIAS, ADMIN_KEY_ALIAS);
                attributes.put(KeystorePasswordStore.KEY_PASSWORD, adminKeyPassword);
                attributes.put(KeystorePasswordStore.KEY_SIZE, String.valueOf(ADMIN_KEY_SIZE));
            }
            credentialStore = CredentialStore.getInstance(KeystorePasswordStore.KEY_STORE_PASSWORD_STORE);
            attributes.put(KeystorePasswordStore.STORE_FILE, credentialStoreFileName);
            attributes.put(KeystorePasswordStore.STORE_PASSWORD, storePassword);
            if (!createStorageFirst) {
                attributes.put(KeystorePasswordStore.CREATE_STORAGE, "true");
                File storage = new File(credentialStoreFileName);
                if (storage.exists()) {
                    storage.delete();
                }
            }
            credentialStore.initialize(attributes);
        } catch (Throwable t) {
            LOGGER.error(t);
            throw new RuntimeException(t);
        }
        LOGGER.debugf("Credential Store created [%s] with master password \"%s\"", credentialStoreFileName, storePassword);
    }

    /**
     * Create Credential Store.
     * Automatically crate underlying KeyStore.
     *
     * @param credentialStoreFileName name of file to hold credentials
     * @param storePassword master password (clear text) to open the credential store
     */
    public CredentialStoreUtility(String credentialStoreFileName, String storePassword) {
        this(credentialStoreFileName, storePassword, storePassword, false);
    }

    /**
     * Create Credential Store with default password.
     * Automatically crate underlying KeyStore.
     *
     * @param credentialStoreFileName name of file to hold credentials
     */
    public CredentialStoreUtility(String credentialStoreFileName) {
        this(credentialStoreFileName, DEFAULT_PASSWORD);
    }

    /**
     * Create Credential Store.
     * Automatically crate underlying KeyStore.
     *
     * @param credentialStoreFileName name of file to hold credentials
     * @param storePassword master password (clear text) to open the credential store
     * @param adminKeyPassword a password (clear text) for protecting admin key
     */
    public CredentialStoreUtility(String credentialStoreFileName, String storePassword, String adminKeyPassword) {
        this(credentialStoreFileName, storePassword, adminKeyPassword, false);
    }

    public void addEntry(String alias, String clearTextPassword) {
        try {
            credentialStore.store(alias, new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, clearTextPassword.toCharArray())));
        } catch (Exception e) {
            LOGGER.error(e);
            throw new RuntimeException(e);
        }
    }

    private void createKeyStore(char[] keyStorePwd, char[] adminKeyPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load((InputStream)null, null);
        ks.setEntry(ADMIN_KEY_ALIAS, new KeyStore.SecretKeyEntry(generateSecretKey()),
                new KeyStore.PasswordProtection(adminKeyPwd) {
        });
        ks.store(new FileOutputStream(new File(credentialStoreFileName)), keyStorePwd);
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(CRYPTO_ALGORITHM);
        generator.init(ADMIN_KEY_SIZE);
        return generator.generateKey();
    }


    /**
     * Delete associated files.
     */
    public void cleanUp() {
        deleteIfExists(new File(credentialStoreFileName));
    }

    public String getCredentialStoreFile() {
        return credentialStoreFileName;
    }

    private static void deleteIfExists(File f) {
        assert !f.exists() || f.delete();
    }

}
