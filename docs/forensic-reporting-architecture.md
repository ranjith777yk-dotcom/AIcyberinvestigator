# Forensic Reporting Architecture

## Reporting principles

Reports are versioned investigation deliverables. Generation never mutates a
prior version, and generated conclusions must not exceed the recorded source
material.

The version 2 document contract separates:

- system-derived summaries of recorded counts;
- source-linked forensic findings;
- investigator-authored notes;
- recorded recommendations;
- provider or analysis-backed intelligence and ATT&CK mappings;
- AI-generated narrative requiring investigator review;
- approval and future digital-signature metadata.

Every forensic finding includes its supporting evidence identifier, evidence
number, and SHA-256 hash. An empty section is preferable to a synthetic finding.

## Lifecycle

1. An authorized investigator requests a report template.
2. The system reserves the next case/template version.
3. A deterministic document is written from current investigation records.
4. Optional AI narrative runs asynchronously and is labeled as AI-generated.
5. Investigator annotations and review state are stored in the report document.
6. Approval records the actor and timestamp.
7. Every generation, AI review, approval, edit, and export operation is audited.

## Export boundary

PDF, DOCX, HTML, Markdown, JSON, and evidence-package exports read the same
versioned report document. Exports never regenerate findings. Unsupported
formats are rejected, and every successful export is audited with its format
and report version.

Digital-signature fields are reserved in the review envelope but remain
explicitly `not_configured` until a managed signing provider and key lifecycle
are implemented.
