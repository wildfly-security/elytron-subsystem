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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.registry.DelegatingResource;
import org.jboss.as.controller.registry.PlaceholderResource;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.controller.security.CredentialStoreClient;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.wildfly.extension.elytron._private.ElytronSubsystemMessages;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * A {@link Resource} to represent a {@link CredentialStoreResourceDefinition}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class CredentialStoreResource extends DelegatingResource {

    private ServiceController<CredentialStoreClient> credentialStoreServiceController;

    CredentialStoreResource(Resource delegate) {
        super(delegate);
    }

    public void setCredentialStoreServiceController(ServiceController<CredentialStoreClient> credentialStoreServiceController) {
        this.credentialStoreServiceController = credentialStoreServiceController;
    }

    @Override
    public Set<String> getChildTypes() {
        if (containsAliases()) {
            return Collections.singleton(ElytronDescriptionConstants.ALIAS);
        }
        return Collections.emptySet();
    }

    @Override
    public boolean hasChildren(String childType) {
        return ElytronDescriptionConstants.ALIAS.equals(childType) && containsAliases();
    }

    @Override
    public boolean hasChild(PathElement element) {
        final CredentialStore credentialStore;
        try {
            if (ElytronDescriptionConstants.ALIAS.equals(element.getKey())) {
                CredentialStoreClient credentialStoreClient = getCredentialStoreClient(credentialStoreServiceController);
                if (credentialStoreClient == null) {
                    return false;
                }
                credentialStore = credentialStoreClient.getCredentialStore();
                if (credentialStore != null && (credentialStore.getAliases().contains(element.getValue()))) {
                    return true;
                }
                return false;
            }
        } catch (CredentialStoreException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.credentialStoreIssueEncountered(e);
        }
        return false;
    }

    @Override
    public Resource getChild(PathElement element) {
        final CredentialStore credentialStore;
        try {
            if (ElytronDescriptionConstants.ALIAS.equals(element.getKey())) {
                CredentialStoreClient credentialStoreClient = getCredentialStoreClient(credentialStoreServiceController);
                if (credentialStoreClient == null) {
                    return null;
                }
                credentialStore = credentialStoreClient.getCredentialStore();
                if (credentialStore != null && (credentialStore.getAliases().contains(element.getValue()))) {
                    return Resource.Factory.create(true);
                }
                return null;
            }
        } catch (CredentialStoreException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.credentialStoreIssueEncountered(e);
        }
        return null;
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
    public Set<String> getChildrenNames(String childType) {
        final CredentialStore credentialStore;
        try {
            if (ElytronDescriptionConstants.ALIAS.equals(childType)) {
                CredentialStoreClient credentialStoreClient = getCredentialStoreClient(credentialStoreServiceController);
                if (credentialStoreClient == null) {
                    credentialStore = null;
                } else {
                    credentialStore = credentialStoreClient.getCredentialStore();
                }
                if (credentialStore != null && credentialStore.isInitialized()) {
                    return credentialStore.getAliases();
                } else {
                    return Collections.emptySet();
                }
            }
        } catch (CredentialStoreException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.credentialStoreIssueEncountered(e);
        }
        return Collections.emptySet();
    }

    @Override
    public Set<ResourceEntry> getChildren(String childType) {
        final CredentialStore credentialStore;
        try {
            if (ElytronDescriptionConstants.ALIAS.equals(childType)) {
                CredentialStoreClient credentialStoreClient = getCredentialStoreClient(credentialStoreServiceController);
                if (credentialStoreClient == null) {
                    credentialStore = null;
                } else {
                    credentialStore = credentialStoreClient.getCredentialStore();
                }
                if (credentialStore != null && credentialStore.isInitialized() && credentialStore.getAliases().size() > 0) {
                    Set<String> aliases = credentialStore.getAliases();
                    Set<ResourceEntry> children = new LinkedHashSet<>(aliases.size());
                    children.addAll(aliases.stream().map(alias -> new PlaceholderResource.PlaceholderResourceEntry(ElytronDescriptionConstants.ALIAS, alias)).collect(Collectors.toList()));
                    return children;
                } else {
                    return Collections.emptySet();
                }
            }
        } catch (CredentialStoreException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.credentialStoreIssueEncountered(e);
        }
        return Collections.emptySet();
    }

    @Override
    public Resource navigate(PathAddress address) {
        return Resource.Tools.navigate(this, address);
    }

    @Override
    public Resource clone() {
        CredentialStoreResource credentialStoreResource = new CredentialStoreResource(super.clone());
        credentialStoreResource.setCredentialStoreServiceController(credentialStoreServiceController);
        return credentialStoreResource;
    }

    private boolean containsAliases() {
        final CredentialStoreClient credentialStoreClient;
        try {
            credentialStoreClient = getCredentialStoreClient(credentialStoreServiceController);
            if (credentialStoreClient == null) {
                return false;
            }
            CredentialStore credentialStore = credentialStoreClient.getCredentialStore();
            return credentialStore != null && credentialStore.isInitialized() && credentialStore.getAliases().size() > 0;
        } catch (CredentialStoreException e) {
            return false;
        }
    }

    /**
     * Get the {@link CredentialStoreClient} represented by this {@link Resource} or {@code null} if it is not currently available.
     *
     * @return The {@link CredentialStoreClient} represented by this {@link Resource} or {@code null} if it is not currently available.
     */
    static CredentialStoreClient getCredentialStoreClient(ServiceController<CredentialStoreClient> credentialStoreServiceController) {
        if (credentialStoreServiceController == null || credentialStoreServiceController.getState() != State.UP) {
            return null;
        } else {
            return credentialStoreServiceController.getValue();
        }
    }

}
