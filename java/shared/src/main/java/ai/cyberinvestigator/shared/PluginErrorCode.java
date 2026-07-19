package ai.cyberinvestigator.shared;

/** Stable error categories shared by Java plugins and the Python orchestrator. */
public enum PluginErrorCode {
    /** The normalized input request is invalid for the plugin. */
    INVALID_REQUEST,
    /** The requested artifact type is not supported by the plugin. */
    UNSUPPORTED_ARTIFACT,
    /** A declared plugin dependency is unavailable. */
    DEPENDENCY_UNAVAILABLE,
    /** The plugin could not complete a valid request. */
    PROCESSING_FAILED,
    /** An unexpected SDK-boundary error occurred. */
    INTERNAL_ERROR
}
