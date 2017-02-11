package org.wildfly.extension.elytron;

import java.util.Set;

import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.capability.RuntimeCapability;

/**
 * Extends the {@link AbstractRemoveStepHandler} overriding the {@link #requiresRuntime(OperationContext)}.
 *
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
abstract class ElytronRemoveStepHandler extends AbstractRemoveStepHandler implements ElytronOperationStepHandler {
    protected ElytronRemoveStepHandler() {
        super();
    }

    protected ElytronRemoveStepHandler(final RuntimeCapability... capabilities) {
        super(capabilities);
    }

    protected ElytronRemoveStepHandler(final Set<RuntimeCapability> capabilities) {
        super(capabilities);
    }

    @Override
    protected boolean requiresRuntime(final OperationContext context) {
        return isServerOrHostController(context);
    }
}
