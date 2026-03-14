//! FTS5 full-text search: indexing, text extraction, and query.
//!
//! Spec: seed-drill/specs/search-indexing.md §2-§4

use rusqlite::{Connection, params};

use cordelia_core::CordeliaError;

/// Maximum query length in characters.
const MAX_QUERY_LEN: usize = 200;

/// Maximum number of terms in a query.
const MAX_QUERY_TERMS: usize = 20;

/// Extracted searchable text from an item's content and metadata.
pub struct SearchableText {
    pub name: String,
    pub summary: String,
    pub content_text: String,
    pub tags_text: String,
}

/// Extract searchable text from item content and metadata.
///
/// Rules per search-indexing.md §3.1:
/// - Memory items (item_type starts with "memory:", content has "name"): extract name/summary/content/tags
/// - Structured content (has "text" field): extract text, tags from metadata
/// - Plain string content: use as content_text
/// - Other JSON: serialize as content_text, tags from metadata
pub fn extract_text(
    content: &serde_json::Value,
    metadata: Option<&serde_json::Value>,
    item_type: &str,
) -> SearchableText {
    // Memory items: memory:entity, memory:learning, memory:session
    if item_type.starts_with("memory:") {
        if let Some(obj) = content.as_object() {
            if obj.contains_key("name") {
                return SearchableText {
                    name: obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    summary: obj
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    content_text: obj
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    tags_text: extract_tags_from_value(content.get("tags")),
                };
            }
        }
    }

    // Structured content with "text" field
    if let Some(text) = content.get("text").and_then(|v| v.as_str()) {
        return SearchableText {
            name: String::new(),
            summary: String::new(),
            content_text: text.to_string(),
            tags_text: extract_tags_from_metadata(metadata),
        };
    }

    // Plain string content
    if let Some(s) = content.as_str() {
        return SearchableText {
            name: String::new(),
            summary: String::new(),
            content_text: s.to_string(),
            tags_text: String::new(),
        };
    }

    // Other JSON: serialize
    SearchableText {
        name: String::new(),
        summary: String::new(),
        content_text: serde_json::to_string(content).unwrap_or_default(),
        tags_text: extract_tags_from_metadata(metadata),
    }
}

/// Index an item for FTS5 search.
///
/// Inserts into search_content; the FTS5 trigger handles the virtual table.
pub fn index_item(
    conn: &Connection,
    item_id: &str,
    channel_id: &str,
    item_type: &str,
    published_at: &str,
    text: &SearchableText,
) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT OR REPLACE INTO search_content
            (item_id, channel_id, item_type, published_at, is_tombstone,
             name, summary, content_text, tags_text)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8)",
        params![
            item_id,
            channel_id,
            item_type,
            published_at,
            text.name,
            text.summary,
            text.content_text,
            text.tags_text,
        ],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    Ok(())
}

/// Mark an item as tombstoned in the search index.
pub fn tombstone_search(conn: &Connection, item_id: &str) -> Result<(), CordeliaError> {
    conn.execute(
        "UPDATE search_content SET is_tombstone = 1 WHERE item_id = ?1",
        params![item_id],
    )
    .map_err(|e| CordeliaError::Storage(e.to_string()))?;
    Ok(())
}

/// A search result row with BM25 score.
pub struct SearchRow {
    pub item_id: String,
    pub score: f64,
}

/// Sanitize and validate a search query.
///
/// Rules per channels-api.md §3.13:
/// - Max 200 characters
/// - Max 20 terms
/// - Prefix queries: min 3 characters before *
/// - Balanced quotes and parentheses
pub fn sanitize_query(query: &str) -> Result<String, CordeliaError> {
    let trimmed = query.trim();

    if trimmed.is_empty() {
        return Err(CordeliaError::Validation("query must not be empty".into()));
    }

    if trimmed.len() > MAX_QUERY_LEN {
        return Err(CordeliaError::Validation(format!(
            "query exceeds {MAX_QUERY_LEN} characters"
        )));
    }

    let terms: Vec<&str> = trimmed.split_whitespace().collect();
    if terms.len() > MAX_QUERY_TERMS {
        return Err(CordeliaError::Validation(format!(
            "query exceeds {MAX_QUERY_TERMS} terms"
        )));
    }

    // Check prefix queries (min 3 chars before *)
    for term in &terms {
        if let Some(pos) = term.find('*') {
            let prefix = &term[..pos];
            // Strip leading quotes/parens
            let clean_prefix = prefix.trim_start_matches(|c: char| c == '"' || c == '(');
            if clean_prefix.len() < 3 {
                return Err(CordeliaError::Validation(
                    "prefix queries require at least 3 characters before *".into(),
                ));
            }
        }
    }

    // Check balanced quotes
    let quote_count = trimmed.chars().filter(|&c| c == '"').count();
    if quote_count % 2 != 0 {
        return Err(CordeliaError::Validation("unbalanced quotes".into()));
    }

    // Check balanced parentheses
    let open = trimmed.chars().filter(|&c| c == '(').count();
    let close = trimmed.chars().filter(|&c| c == ')').count();
    if open != close {
        return Err(CordeliaError::Validation("unbalanced parentheses".into()));
    }

    Ok(trimmed.to_string())
}

/// Execute an FTS5 search within a channel.
///
/// Returns item_ids with normalised BM25 scores (0-1, higher is better).
/// Filters out tombstoned items and optionally by item_type and since.
pub fn search_fts(
    conn: &Connection,
    channel_id: &str,
    query: &str,
    limit: u32,
    types: Option<&[String]>,
    since: Option<&str>,
) -> Result<Vec<SearchRow>, CordeliaError> {
    let sanitized = sanitize_query(query)?;

    // Build the SQL with optional filters
    // We join search_fts (for matching + rank) with search_content (for filtering)
    let mut sql = String::from(
        "SELECT sc.item_id, f.rank
         FROM search_fts f
         JOIN search_content sc ON sc.rowid = f.rowid
         WHERE search_fts MATCH ?1
           AND sc.channel_id = ?2
           AND sc.is_tombstone = 0",
    );

    if types.is_some() {
        // Placeholder will be built dynamically
        sql.push_str(" AND sc.item_type IN (");
    }

    if since.is_some() {
        sql.push_str(" AND sc.published_at > ?");
    }

    sql.push_str(" ORDER BY f.rank LIMIT ?");

    // Use a simpler approach: build the full query with all parameters
    // Because rusqlite doesn't support dynamic IN clauses easily,
    // we'll filter types in Rust after the query if needed.
    let base_sql = "SELECT sc.item_id, f.rank
         FROM search_fts f
         JOIN search_content sc ON sc.rowid = f.rowid
         WHERE search_fts MATCH ?1
           AND sc.channel_id = ?2
           AND sc.is_tombstone = 0
         ORDER BY f.rank
         LIMIT ?3";

    // Over-fetch to allow post-filtering
    let fetch_limit = if types.is_some() || since.is_some() {
        limit * 3
    } else {
        limit
    };

    let mut stmt = conn
        .prepare(base_sql)
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let rows = stmt
        .query_map(params![sanitized, channel_id, fetch_limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })
        .map_err(|e| CordeliaError::Storage(e.to_string()))?;

    let mut raw_results: Vec<(String, f64)> = Vec::new();
    for row in rows {
        raw_results.push(row.map_err(|e| CordeliaError::Storage(e.to_string()))?);
    }

    // Post-filter by types and since if needed
    if types.is_some() || since.is_some() {
        // We need to look up item_type and published_at for filtering
        let mut filtered = Vec::new();
        for (item_id, rank) in &raw_results {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT item_type, published_at FROM search_content WHERE item_id = ?1",
                    params![item_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();

            if let Some((item_type, published_at)) = row {
                if let Some(type_filter) = types {
                    if !type_filter.iter().any(|t| t == &item_type) {
                        continue;
                    }
                }
                if let Some(since_val) = since {
                    if published_at.as_str() <= since_val {
                        continue;
                    }
                }
                filtered.push((item_id.clone(), *rank));
            }
        }
        raw_results = filtered;
    }

    // Truncate to limit
    raw_results.truncate(limit as usize);

    // Normalise BM25 scores: raw scores are negative (more negative = better match)
    // Normalise to 0-1 where 1 = best match
    let best_raw = raw_results
        .iter()
        .map(|(_, s)| *s)
        .fold(f64::INFINITY, f64::min);

    let results = raw_results
        .into_iter()
        .map(|(item_id, rank)| {
            let score = if best_raw < 0.0 {
                rank / best_raw // both negative, so this gives 0-1 range
            } else {
                1.0
            };
            SearchRow {
                item_id,
                score: score.clamp(0.0, 1.0),
            }
        })
        .collect();

    Ok(results)
}

// ── Internal helpers ──────────────────────────────────────────────

/// Extract space-separated tags from a JSON array value.
fn extract_tags_from_value(tags: Option<&serde_json::Value>) -> String {
    match tags {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// Extract space-separated tags from metadata.tags array.
fn extract_tags_from_metadata(metadata: Option<&serde_json::Value>) -> String {
    metadata
        .and_then(|m| m.get("tags"))
        .map(|tags| extract_tags_from_value(Some(tags)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup() -> Connection {
        let conn = db::open_in_memory().unwrap();
        // Create a test channel
        conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch1', 'test', 'named', 'realtime', 'open', X'0000000000000000000000000000000000000000000000000000000000000042', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn
    }

    // ── Text Extraction ──────────────────────────────────────

    #[test]
    fn test_extract_memory_item() {
        let content = serde_json::json!({
            "name": "Vector search patterns",
            "summary": "How to use sqlite-vec",
            "content": "Full content about vector search techniques",
            "tags": ["search", "vectors"]
        });
        let text = extract_text(&content, None, "memory:learning");
        assert_eq!(text.name, "Vector search patterns");
        assert_eq!(text.summary, "How to use sqlite-vec");
        assert_eq!(
            text.content_text,
            "Full content about vector search techniques"
        );
        assert_eq!(text.tags_text, "search vectors");
    }

    #[test]
    fn test_extract_structured_content() {
        let content = serde_json::json!({ "text": "Hello world" });
        let metadata = serde_json::json!({ "tags": ["greeting", "test"] });
        let text = extract_text(&content, Some(&metadata), "message");
        assert_eq!(text.name, "");
        assert_eq!(text.content_text, "Hello world");
        assert_eq!(text.tags_text, "greeting test");
    }

    #[test]
    fn test_extract_plain_string() {
        let content = serde_json::Value::String("Just a plain string".into());
        let text = extract_text(&content, None, "message");
        assert_eq!(text.content_text, "Just a plain string");
        assert_eq!(text.tags_text, "");
    }

    #[test]
    fn test_extract_other_json() {
        let content = serde_json::json!({ "x": 1, "y": 2 });
        let metadata = serde_json::json!({ "tags": ["data"] });
        let text = extract_text(&content, Some(&metadata), "event");
        assert!(text.content_text.contains("\"x\""));
        assert_eq!(text.tags_text, "data");
    }

    // ── Query Sanitization ───────────────────────────────────

    #[test]
    fn test_sanitize_valid_query() {
        assert_eq!(sanitize_query("hello world").unwrap(), "hello world");
    }

    #[test]
    fn test_sanitize_empty_query() {
        assert!(sanitize_query("").is_err());
        assert!(sanitize_query("   ").is_err());
    }

    #[test]
    fn test_sanitize_too_long() {
        let long = "a ".repeat(101);
        assert!(sanitize_query(&long).is_err());
    }

    #[test]
    fn test_sanitize_too_many_terms() {
        let many = (0..21)
            .map(|i| format!("term{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(sanitize_query(&many).is_err());
    }

    #[test]
    fn test_sanitize_prefix_too_short() {
        assert!(sanitize_query("ab*").is_err());
        assert!(sanitize_query("a*").is_err());
        assert!(sanitize_query("abc*").is_ok());
    }

    #[test]
    fn test_sanitize_unbalanced_quotes() {
        assert!(sanitize_query("\"hello").is_err());
        assert!(sanitize_query("\"hello\"").is_ok());
    }

    #[test]
    fn test_sanitize_unbalanced_parens() {
        assert!(sanitize_query("(hello").is_err());
        assert!(sanitize_query("(hello)").is_ok());
    }

    #[test]
    fn test_sanitize_fts5_operators() {
        assert!(sanitize_query("hello AND world").is_ok());
        assert!(sanitize_query("hello OR world").is_ok());
        assert!(sanitize_query("hello NOT world").is_ok());
    }

    // ── FTS5 Search ──────────────────────────────────────────

    #[test]
    fn test_index_and_search() {
        let conn = setup();

        let text1 = SearchableText {
            name: "Vector search".into(),
            summary: "Using sqlite-vec".into(),
            content_text: "Full-text search with BM25 ranking".into(),
            tags_text: "search vectors".into(),
        };
        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text1,
        )
        .unwrap();

        let text2 = SearchableText {
            name: "Encryption patterns".into(),
            summary: "AES-GCM usage".into(),
            content_text: "How to encrypt data with AES-256-GCM".into(),
            tags_text: "crypto encryption".into(),
        };
        index_item(
            &conn,
            "ci_002",
            "ch1",
            "message",
            "2026-01-01T00:02:00Z",
            &text2,
        )
        .unwrap();

        // Search for "search"
        let results = search_fts(&conn, "ch1", "search", 10, None, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item_id, "ci_001");
        assert!(results[0].score > 0.0);
        assert!(results[0].score <= 1.0);
    }

    #[test]
    fn test_search_no_results() {
        let conn = setup();

        let text = SearchableText {
            name: "Hello".into(),
            summary: "".into(),
            content_text: "World".into(),
            tags_text: "".into(),
        };
        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();

        let results = search_fts(&conn, "ch1", "nonexistent", 10, None, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_channel_scoped() {
        let conn = setup();

        // Create a second channel
        conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch2', 'other', 'named', 'realtime', 'open', X'0000000000000000000000000000000000000000000000000000000000000042', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        ).unwrap();

        let text = SearchableText {
            name: "".into(),
            summary: "".into(),
            content_text: "searchable content".into(),
            tags_text: "".into(),
        };

        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();
        index_item(
            &conn,
            "ci_002",
            "ch2",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();

        // Search ch1 only
        let results = search_fts(&conn, "ch1", "searchable", 10, None, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item_id, "ci_001");
    }

    #[test]
    fn test_search_excludes_tombstoned() {
        let conn = setup();

        let text = SearchableText {
            name: "".into(),
            summary: "".into(),
            content_text: "findable content".into(),
            tags_text: "".into(),
        };
        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();

        // Tombstone it
        tombstone_search(&conn, "ci_001").unwrap();

        let results = search_fts(&conn, "ch1", "findable", 10, None, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_with_type_filter() {
        let conn = setup();

        let text = SearchableText {
            name: "test".into(),
            summary: "".into(),
            content_text: "searchable data".into(),
            tags_text: "".into(),
        };

        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();
        index_item(
            &conn,
            "ci_002",
            "ch1",
            "event",
            "2026-01-01T00:02:00Z",
            &text,
        )
        .unwrap();

        let types = vec!["event".to_string()];
        let results = search_fts(&conn, "ch1", "searchable", 10, Some(&types), None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item_id, "ci_002");
    }

    #[test]
    fn test_search_with_since_filter() {
        let conn = setup();

        let text = SearchableText {
            name: "".into(),
            summary: "".into(),
            content_text: "temporal data".into(),
            tags_text: "".into(),
        };

        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text,
        )
        .unwrap();
        index_item(
            &conn,
            "ci_002",
            "ch1",
            "message",
            "2026-01-02T00:01:00Z",
            &text,
        )
        .unwrap();

        let results = search_fts(
            &conn,
            "ch1",
            "temporal",
            10,
            None,
            Some("2026-01-01T12:00:00Z"),
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].item_id, "ci_002");
    }

    #[test]
    fn test_search_bm25_score_normalisation() {
        let conn = setup();

        // Item with many mentions of "search"
        let text1 = SearchableText {
            name: "search".into(),
            summary: "search techniques".into(),
            content_text: "search search search algorithms for search".into(),
            tags_text: "search".into(),
        };
        index_item(
            &conn,
            "ci_001",
            "ch1",
            "message",
            "2026-01-01T00:01:00Z",
            &text1,
        )
        .unwrap();

        // Item with fewer mentions
        let text2 = SearchableText {
            name: "other".into(),
            summary: "".into(),
            content_text: "a brief mention of search".into(),
            tags_text: "".into(),
        };
        index_item(
            &conn,
            "ci_002",
            "ch1",
            "message",
            "2026-01-01T00:02:00Z",
            &text2,
        )
        .unwrap();

        let results = search_fts(&conn, "ch1", "search", 10, None, None).unwrap();
        assert_eq!(results.len(), 2);
        // Best match should have score 1.0
        assert!((results[0].score - 1.0).abs() < 0.01);
        // Second match should be lower
        assert!(results[1].score < 1.0);
        assert!(results[1].score > 0.0);
    }
}
