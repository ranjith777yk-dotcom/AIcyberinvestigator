package ai.cyberinvestigator.shared;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Standard-library {@link PluginLogger} adapter for SDK consumers. */
public final class JavaUtilPluginLogger implements PluginLogger {
    private final Logger logger;

    /** Creates an adapter for a supplied Java Util Logging logger. */
    public JavaUtilPluginLogger(Logger logger) {
        this.logger = Objects.requireNonNull(logger, "logger must not be null");
    }

    /** Creates an adapter scoped to a plugin implementation class. */
    public static JavaUtilPluginLogger forPlugin(Class<?> pluginClass) {
        return new JavaUtilPluginLogger(Logger.getLogger(pluginClass.getName()));
    }

    @Override
    public void info(String message) {
        logger.info(message);
    }

    @Override
    public void warn(String message) {
        logger.warning(message);
    }

    @Override
    public void error(String message, Throwable error) {
        logger.log(Level.SEVERE, message, error);
    }
}
