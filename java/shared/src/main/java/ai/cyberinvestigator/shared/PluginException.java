package ai.cyberinvestigator.shared;

/** Checked exception used by plugins to report a safe, structured processing failure. */
public final class PluginException extends Exception {
    private final PluginErrorCode errorCode;

    /**
     * Creates a structured plugin failure.
     *
     * @param errorCode stable error category
     * @param message safe message that may be returned to Python
     */
    public PluginException(PluginErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /** Returns the stable error category for this failure. */
    public PluginErrorCode errorCode() {
        return errorCode;
    }
}
