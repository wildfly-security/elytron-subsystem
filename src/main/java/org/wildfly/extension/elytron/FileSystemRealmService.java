/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.extension.elytron;

import java.nio.file.Path;

import org.jboss.as.controller.services.path.PathManager;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.provider.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * @author Kabir Khan
 */
public class FileSystemRealmService implements Service<SecurityRealm> {

    private volatile SecurityRealm securityRealm;

    private final int levels;
    private final String path;
    private final String relativeTo;
    private final InjectedValue<PathManager> pathManagerInjector = new InjectedValue<PathManager>();
    private final InjectedValue<NameRewriter> nameRewriterInjector = new InjectedValue<>();

    public FileSystemRealmService(int levels, String path, String relativeTo) {
        this.levels = levels;
        this.path = path;
        this.relativeTo = relativeTo;
    }

    @Override
    public void start(StartContext context) throws StartException {
        Path path = null;
        securityRealm = nameRewriterInjector != null ?
                new FileSystemSecurityRealm(path, nameRewriterInjector.getValue(), levels) :
                new FileSystemSecurityRealm(path, levels);
    }

    @Override
    public void stop(StopContext context) {
        securityRealm = null;
    }

    @Override
    public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
        return securityRealm;
    }

    public InjectedValue<PathManager> getPathManagerInjector() {
        return pathManagerInjector;
    }

    public InjectedValue<NameRewriter> getNameRewriterInjector() {
        return nameRewriterInjector;
    }
}
