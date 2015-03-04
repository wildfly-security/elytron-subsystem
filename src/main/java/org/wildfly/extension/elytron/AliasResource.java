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

import static org.wildfly.extension.elytron.KeyStoreResource.getKeyStore;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.registry.DelegatingResource;
import org.jboss.as.controller.registry.PlaceholderResource;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.registry.Resource.NoSuchResourceException;
import org.jboss.msc.service.ServiceController;

/**
 * A {@link Resource} to represent a {@link KeyStoreAliasDefinition}, this is primarily to represent the appropriate type of certificate chain.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AliasResource extends DelegatingResource {

    private final String alias;
    private final ServiceController<KeyStore> keyStoreServiceController;

    AliasResource(String alias, ServiceController<KeyStore> keyStoreServiceController) {
        super(Resource.Factory.create(true));
        this.alias = alias;
        this.keyStoreServiceController = keyStoreServiceController;
    }

    private AliasResource(String alias, ServiceController<KeyStore> keyStoreServiceController, Resource delegate) {
        super(delegate);
        this.alias = alias;
        this.keyStoreServiceController = keyStoreServiceController;
    }

    @Override
    public boolean hasChildren(String childType) {
        if (ElytronDescriptionConstants.CERTIFICATE_CHAIN.equals(childType) && chainType() != null) {
            return true;
        }

        return super.hasChildren(childType);
    }

    @Override
    public Resource getChild(PathElement element) {
        ChainType chainType;
        if (ElytronDescriptionConstants.CERTIFICATE_CHAIN.equals(element.getKey()) && (chainType = chainType()) != null && element.getValue().equals(chainType.getModelValue())) {
            return PlaceholderResource.INSTANCE;
        }

        return super.getChild(element);
    }

    @Override
    public Set<ResourceEntry> getChildren(String childType) {
        ChainType chainType;
        if (ElytronDescriptionConstants.CERTIFICATE_CHAIN.equals(childType) && (chainType = chainType()) != null) {
            ResourceEntry resourceEntry = new PlaceholderResource.PlaceholderResourceEntry(ElytronDescriptionConstants.CERTIFICATE_CHAIN, chainType.getModelValue());
            return Collections.singleton(resourceEntry);
        }

        return super.getChildren(childType);
    }

    @Override
    public Set<String> getChildrenNames(String childType) {
        ChainType chainType;
        if (ElytronDescriptionConstants.CERTIFICATE_CHAIN.equals(childType) && (chainType = chainType()) != null) {
            return Collections.singleton(chainType.getModelValue());
        }

        return super.getChildrenNames(childType);
    }

    @Override
    public Set<String> getChildTypes() {
        if (chainType() != null) {
            return Collections.singleton(ElytronDescriptionConstants.CERTIFICATE_CHAIN);
        }

        return super.getChildTypes();
    }

    @Override
    public boolean hasChild(PathElement element) {
        ChainType chainType;
        if (ElytronDescriptionConstants.CERTIFICATE_CHAIN.equals(element.getKey()) && (chainType = chainType()) != null && element.getValue().equals(chainType.getModelValue())) {
            return true;
        }

        return super.hasChild(element);
    }

    @Override
    public Resource requireChild(PathElement element) {
        Resource resource = getChild(element);
        if (resource == null) {
            throw new NoSuchResourceException(element);
        }
        return resource;
    }

    @Override
    public Resource navigate(PathAddress address) {
        return Resource.Tools.navigate(this, address);
    }

    @Override
    public Resource clone() {
        Resource clonedDelegate = super.clone();
        return new AliasResource(alias, keyStoreServiceController, clonedDelegate);
    }

    private ChainType chainType() {
        KeyStore keyStore;
        Certificate[] chain;
        try {
            if ((keyStore= getKeyStore(keyStoreServiceController)) != null && keyStore.containsAlias(alias) &&
                    (chain = keyStore.getCertificateChain(alias)) != null && chain.length > 0) {
                return chain[0] instanceof X509Certificate ? ChainType.X509 : ChainType.DEFAULT;
            }
        } catch (KeyStoreException e) {
            return null;
        }

        return null;
    }

    private enum ChainType {

        DEFAULT(ElytronDescriptionConstants.DEFAULT), X509(ElytronDescriptionConstants.X509);

        private final String modelValue;

        ChainType(final String modelValue) {
            this.modelValue = modelValue;
        }

        String getModelValue() {
            return modelValue;
        }

    }

    public static class AliasResourceEntry extends AliasResource implements ResourceEntry {

        private final PathElement pathElement;

        AliasResourceEntry(PathElement pathElement, ServiceController<KeyStore> keyStoreServiceController) {
            super(pathElement.getValue(), keyStoreServiceController);
            this.pathElement = pathElement;
        }

        @Override
        public String getName() {
            return pathElement.getValue();
        }

        @Override
        public PathElement getPathElement() {
            return pathElement;
        }

    }
}
