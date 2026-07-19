package ai.cyberinvestigator.shared;

/** Status values serialized in every Java plugin JSON response. */
public enum PluginResponseStatus {
    /** The plugin completed and returned a JSON payload. */
    SUCCEEDED,
    /** The plugin returned a handled or unexpected failure. */
    FAILED
}
