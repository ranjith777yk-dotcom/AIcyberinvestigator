package ai.cyberinvestigator.shared;

import java.util.List;
import java.util.Objects;

/** Immutable metadata required for every Java plugin manifest and SDK contract. */
public record PluginMetadata(
        String name,
        String version,
        String author,
        String description,
        List<String> supportedArtifactTypes,
        List<String> supportedInvestigationStages,
        String requiredJavaVersion) {

    /** Validates mandatory metadata and defensively copies collection values. */
    public PluginMetadata {
        name = requireText(name, "name");
        version = requireText(version, "version");
        author = requireText(author, "author");
        description = requireText(description, "description");
        requiredJavaVersion = requireText(requiredJavaVersion, "requiredJavaVersion");
        supportedArtifactTypes = List.copyOf(Objects.requireNonNull(
                supportedArtifactTypes, "supportedArtifactTypes must not be null"));
        supportedInvestigationStages = List.copyOf(Objects.requireNonNull(
                supportedInvestigationStages, "supportedInvestigationStages must not be null"));
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }
}
