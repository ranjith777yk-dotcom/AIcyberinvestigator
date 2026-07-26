# ADR 0008: Provenance-first intelligence graph

## Status

Accepted

## Decision

Persist normalized indicators, sourced intelligence objects, and relationships
as separate tenant-scoped records. Keep evidence observations, provider
assertions, analyst imports, detections, and AI output distinct.

Build the graph from stored relationships plus read-only links to existing
evidence, investigations, reports, timelines, and detections. Do not create
threat actors, campaigns, malware, CVEs, attribution, or confidence through
inference. Prepare STIX/TAXII through an unavailable-by-default adapter contract.

## Consequences

The platform gains lifecycle management and navigable intelligence context while
remaining truthful about provenance and provider availability. Graph consumers
must interpret `verified`, `provenance`, and `confidence` together rather than
treating every edge as a confirmed relationship.
