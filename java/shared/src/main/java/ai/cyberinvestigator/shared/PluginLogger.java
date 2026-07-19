package ai.cyberinvestigator.shared;

/** Injectable logging contract for Java plugins. */
public interface PluginLogger {
    /** Records an informational SDK or plugin lifecycle event. */
    void info(String message);

    /** Records a warning that does not stop plugin processing. */
    void warn(String message);

    /** Records an error and its internal cause without adding it to JSON output. */
    void error(String message, Throwable error);
}
