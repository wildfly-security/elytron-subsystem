package org.wildfly.extension.elytron;

import org.jboss.as.controller.AbstractRuntimeOnlyHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.dmr.ModelNode;

/**
 * Extends the {@link AbstractRuntimeOnlyHandler} only {@linkplain #execute(OperationContext, ModelNode) executing} the
 * if the {@link #isServerOrHostController(OperationContext)} returns {@code true}.
 *
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
abstract class ElytronRuntimeOnlyHandler extends AbstractRuntimeOnlyHandler implements ElytronOperationStepHandler {
    @Override
    public void execute(final OperationContext context, final ModelNode operation) throws OperationFailedException {
        if (isServerOrHostController(context)) {
            super.execute(context, operation);
        }
    }
}
