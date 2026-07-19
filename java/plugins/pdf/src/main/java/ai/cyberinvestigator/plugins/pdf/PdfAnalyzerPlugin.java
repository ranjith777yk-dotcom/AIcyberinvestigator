package ai.cyberinvestigator.plugins.pdf;

import ai.cyberinvestigator.shared.AbstractJavaInvestigationPlugin;
import ai.cyberinvestigator.shared.PluginErrorCode;
import ai.cyberinvestigator.shared.PluginException;
import ai.cyberinvestigator.shared.PluginMetadata;
import ai.cyberinvestigator.shared.PluginRequest;
import ai.cyberinvestigator.shared.PluginLogger;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;

/**
 * SDK-compliant PDF structural analyzer.
 *
 * <p>The analyzer reads the PDF path supplied in {@code payload.pdf_path},
 * extracts document metadata, counts pages, and detects embedded-file and
 * JavaScript indicators. It does not call AI services or extract page text.</p>
 */
public final class PdfAnalyzerPlugin extends AbstractJavaInvestigationPlugin {
    private static final String PDF_PATH = "pdf_path";
    private static final COSName EMBEDDED_FILE_TYPE = COSName.getPDFName("EmbeddedFile");
    private static final COSName JAVASCRIPT_ACTION = COSName.getPDFName("JavaScript");

    /** Creates the analyzer with the SDK's standard logger. */
    public PdfAnalyzerPlugin() {
        super();
    }

    /** Creates the analyzer with an injected logger for integration testing or hosting. */
    public PdfAnalyzerPlugin(PluginLogger logger) {
        super(logger);
    }

    /** Returns immutable metadata for dynamic Python plugin discovery. */
    @Override
    public PluginMetadata metadata() {
        return new PluginMetadata(
                "pdf-analyzer",
                "0.1.0-SNAPSHOT",
                "CyberInvestigator AI",
                "Extracts PDF metadata and structural indicators without AI integration.",
                List.of("pdf"),
                List.of("triage", "artifact_analysis"),
                "21");
    }

    /** Validates that the SDK payload declares one existing PDF file path. */
    @Override
    protected void validate(PluginRequest request) throws PluginException {
        Object candidate = request.payload().get(PDF_PATH);
        if (!(candidate instanceof String pathValue) || pathValue.isBlank()) {
            throw new PluginException(PluginErrorCode.INVALID_REQUEST, "payload.pdf_path must be a non-empty string.");
        }
        Path path = Path.of(pathValue).normalize();
        if (!Files.isRegularFile(path)) {
            throw new PluginException(PluginErrorCode.INVALID_REQUEST, "payload.pdf_path must reference an existing file.");
        }
        if (!path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".pdf")) {
            throw new PluginException(PluginErrorCode.UNSUPPORTED_ARTIFACT, "The supplied artifact is not a PDF file.");
        }
    }

    /** Reads the PDF and returns only structured metadata and structural indicators. */
    @Override
    protected Map<String, Object> process(PluginRequest request) throws PluginException {
        Path pdfPath = Path.of((String) request.payload().get(PDF_PATH)).normalize();
        try (PDDocument document = Loader.loadPDF(pdfPath.toFile())) {
            COSDocument cosDocument = document.getDocument();
            StructuralIndicators indicators = inspectStructure(cosDocument);
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("file_name", pdfPath.getFileName().toString());
            output.put("page_count", document.getNumberOfPages());
            output.put("is_encrypted", document.isEncrypted());
            output.put("metadata", metadata(document.getDocumentInformation()));
            output.put("embedded_objects", Map.of(
                    "detected", indicators.embeddedObjectCount() > 0,
                    "count", indicators.embeddedObjectCount()));
            output.put("javascript", Map.of(
                    "detected", indicators.javaScriptObjectCount() > 0,
                    "count", indicators.javaScriptObjectCount()));
            return Map.copyOf(output);
        } catch (IOException error) {
            throw new PluginException(PluginErrorCode.PROCESSING_FAILED, "The PDF document could not be read.");
        }
    }

    /** Extracts non-null document information fields into a JSON-safe map. */
    private static Map<String, Object> metadata(PDDocumentInformation information) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        addIfPresent(metadata, "title", information.getTitle());
        addIfPresent(metadata, "author", information.getAuthor());
        addIfPresent(metadata, "subject", information.getSubject());
        addIfPresent(metadata, "keywords", information.getKeywords());
        addIfPresent(metadata, "creator", information.getCreator());
        addIfPresent(metadata, "producer", information.getProducer());
        if (information.getCreationDate() != null) {
            metadata.put("creation_date", information.getCreationDate().toInstant().toString());
        }
        if (information.getModificationDate() != null) {
            metadata.put("modification_date", information.getModificationDate().toInstant().toString());
        }
        return Map.copyOf(metadata);
    }

    /** Adds one non-blank metadata field without serializing null values. */
    private static void addIfPresent(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }

    /** Inspects COS dictionaries for embedded-file streams and JavaScript actions. */
    private static StructuralIndicators inspectStructure(COSDocument document) {
        int embeddedObjects = document.getObjectsByType(EMBEDDED_FILE_TYPE).size();
        int javaScriptObjects = document.getObjectsByType(JAVASCRIPT_ACTION).size();
        return new StructuralIndicators(embeddedObjects, javaScriptObjects);
    }

    /** Immutable structural indicators retained only as JSON-safe output counts. */
    private record StructuralIndicators(int embeddedObjectCount, int javaScriptObjectCount) {
    }
}
