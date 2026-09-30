# Search and Indexing Specification

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-12
**Scope**: Phase 1 (Encrypted Pub/Sub MVP) with Phase 2 forward references
**Depends on**: specs/channels-api.md, specs/memory-model.md, specs/ecies-envelope-encryption.md
**Informs**: SDK search interface, MCP memory_search tool

---

## 1. Architecture Overview

Search in Cordelia is local. All indexing and querying happens at the edge on decrypted plaintext. The network never searches encrypted content, never transmits indexes, and never replicates search state. Each node builds and maintains its own indexes from items it decrypts locally.

### 1.1 Design Principles

1. **Edge-only.** Indexes exist in the local node's SQLite database. They are never transmitted on the wire, never included in replication, and rebuilt locally from decrypted content on each node.
2. **Two signals.** FTS5 provides keyword-precise matching (names, error codes, identifiers). sqlite-vec provides semantic similarity (conceptual queries). The hybrid scorer combines both per-result.
3. **Sync FTS5, async embeddings.** FTS5 indexing is synchronous on write (item is immediately searchable by keyword). Embedding generation is asynchronous (item is searchable by semantic similarity once the embedding completes).
4. **Graceful degradation.** If the embedding model is unavailable, search operates in FTS5-only mode. Results are scored by BM25 alone.
5. **Channel-scoped.** All queries require a channel_id. No cross-channel search in Phase 1.

### 1.2 Data Flow

```
Publish / Replicate
        |
        v
  Decrypt item (AES-256-GCM with channel PSK)
        |
        +---> FTS5 index (synchronous)
        |         |
        |         v
        |     Item immediately searchable by keyword
        |
        +---> Embedding queue (asynchronous)
                  |
                  v
              Ollama API (localhost:11434)
                  |
                  v
              sqlite-vec table (item searchable by semantic similarity)
```

```
Search query
     |
     +---> FTS5 MATCH (BM25 score, normalised 0-1)
     |
     +---> sqlite-vec cosine similarity (normalised 0-1)
     |
     v
  Dominant-signal hybrid scorer
     |
     v
  Ranked results (filtered by channel_id, types, since)
```

---

## 2. SQLite Schema

All search indexes reside in the node's SQLite database (`~/.cordelia/cordelia.db`, mode 0600). The indexes are co-located with the encrypted item store but contain decrypted plaintext.

### 2.1 Items Table (Reference)

The items table is owned by the storage layer, not this spec. It is referenced here for context. The authoritative column set is defined by the node's schema migrations. The columns relevant to search indexing are:

```
item_id       TEXT PRIMARY KEY    -- "ci_" + ULID (26 chars)
channel_id    TEXT NOT NULL       -- hex(SHA-256("cordelia:channel:" + name))
author_id     BLOB NOT NULL       -- Ed25519 public key (32 bytes)
item_type     TEXT NOT NULL       -- "message", "memory:entity", etc.
published_at  TEXT NOT NULL       -- ISO 8601 timestamp
content_hash  BLOB NOT NULL       -- SHA-256 of `encrypted_blob` column value (computed over ciphertext, not plaintext)
encrypted_blob BLOB NOT NULL      -- iv || ciphertext || auth_tag
is_tombstone  INTEGER DEFAULT 0   -- 1 = soft-deleted
parent_id     TEXT                 -- optional threading reference
```

### 2.2 FTS5 Table

FTS5 uses the external content table pattern. The FTS5 index does not duplicate the source text -- it stores only the inverted index and references the content table via rowid. This reduces storage overhead and ensures a single source of truth.

```sql
-- Content table: stores decrypted text for FTS5 indexing.
-- Populated at index time from decrypted item content.
CREATE TABLE search_content (
    rowid         INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id       TEXT NOT NULL UNIQUE,
    channel_id    TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    is_tombstone  INTEGER NOT NULL DEFAULT 0,

    -- Indexed text fields (decrypted plaintext)
    name          TEXT NOT NULL DEFAULT '',     -- memory item name (empty for non-memory items)
    summary       TEXT NOT NULL DEFAULT '',     -- memory item summary (empty if absent)
    content_text  TEXT NOT NULL DEFAULT '',     -- primary content (see §3.1 for extraction rules)
    tags_text     TEXT NOT NULL DEFAULT ''      -- space-separated tags (empty if absent)
);

CREATE INDEX idx_search_content_channel ON search_content(channel_id);
CREATE INDEX idx_search_content_item_id ON search_content(item_id);
CREATE INDEX idx_search_content_type    ON search_content(channel_id, item_type);
```

```sql
-- FTS5 virtual table using external content table pattern.
-- content= links to search_content; content_rowid= maps FTS5 rowid to search_content rowid.
CREATE VIRTUAL TABLE search_fts USING fts5(
    name,
    summary,
    content_text,
    tags_text,
    content = 'search_content',
    content_rowid = 'rowid',
    tokenize = 'unicode61'
);
```

**Synchronisation triggers.** FTS5 external content tables require explicit synchronisation. The node MUST maintain the FTS5 index via triggers or application-level inserts. Triggers are preferred for consistency:

```sql
-- Insert trigger: index new content
CREATE TRIGGER search_fts_insert AFTER INSERT ON search_content BEGIN
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;

-- Delete trigger: remove from index (used for tombstones)
CREATE TRIGGER search_fts_delete AFTER DELETE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
END;

-- Update trigger: re-index on content change
CREATE TRIGGER search_fts_update AFTER UPDATE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;
```

**VACUUM and rebuild.** After `VACUUM`, FTS5 external content table rowid mappings may become invalid because `VACUUM` can reassign rowids in the content table. After any `VACUUM` operation, a full FTS5 rebuild is required (`INSERT INTO search_fts(search_fts) VALUES('rebuild')`).

**Tokenizer choice.** `unicode61` is the FTS5 default. It handles Unicode properly (case folding, diacritics removal) and does not require ICU. Sufficient for Phase 1 English-primary workloads. Phase 2 evaluates `trigram` tokenizer for substring matching and CJK support.

### 2.3 Vector Table

sqlite-vec stores embedding vectors for semantic similarity search. vec0 virtual tables only support integer rowid keys, so a mapping table links `item_id` to the vec0 rowid.

```sql
-- Mapping table: links item_id to vec0 rowid.
-- Required because vec0 virtual tables only support integer rowid keys.
CREATE TABLE search_vec_map (
    rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id     TEXT NOT NULL UNIQUE,
    channel_id  TEXT NOT NULL
);

CREATE INDEX idx_search_vec_map_channel ON search_vec_map(channel_id);
CREATE INDEX idx_search_vec_map_item ON search_vec_map(item_id);

-- Virtual table for vector similarity search.
-- FLOAT[768] stores a 768-dimensional float32 vector (3072 bytes per row).
-- vec0 only supports integer rowid keys; item_id mapping via search_vec_map.
CREATE VIRTUAL TABLE search_vec USING vec0(
    embedding     FLOAT[768]
);
```

### 2.4 Embedding Metadata Table

Tracks embedding generation state per item. Enables cache invalidation when content changes and backfill of missing embeddings.

```sql
CREATE TABLE search_embedding_meta (
    item_id         TEXT PRIMARY KEY,
    channel_id      TEXT NOT NULL,
    content_hash    TEXT NOT NULL,         -- SHA-256 hex of embeddable text (cache key)
    model           TEXT NOT NULL,         -- e.g. "nomic-embed-text-v1.5"
    model_version   TEXT NOT NULL,         -- e.g. "1.5"
    dimensions      INTEGER NOT NULL,      -- e.g. 768
    generated_at    TEXT NOT NULL,          -- ISO 8601 timestamp
    status          TEXT NOT NULL DEFAULT 'pending'  -- "pending", "complete", "failed", "stale"
);

CREATE INDEX idx_embedding_meta_channel ON search_embedding_meta(channel_id);
CREATE INDEX idx_embedding_meta_status  ON search_embedding_meta(status);
```

**Status transitions:**

```
(new item) ---> "pending" ---> "complete"     (successful embedding generation)
                    |
                    +-------> "failed"        (Ollama error, retryable)

"complete" ---> "stale"                       (content changed, content_hash mismatch)
"stale"    ---> "pending"                     (re-queued for embedding)
"failed"   ---> "pending"                     (retried by backfill)
```

### 2.5 Index State Table

Tracks overall index health per channel. Used by the reindex command and backfill tool.

```sql
CREATE TABLE search_index_state (
    channel_id           TEXT PRIMARY KEY,
    last_indexed_item_id TEXT,              -- most recent item_id successfully indexed
    last_indexed_at      TEXT,              -- ISO 8601 timestamp of last index operation
    total_indexed        INTEGER DEFAULT 0, -- count of items in FTS5 index for this channel
    total_embedded       INTEGER DEFAULT 0, -- count of items with complete embeddings
    schema_version       INTEGER DEFAULT 1, -- index schema version (for migration detection)
    needs_rebuild        INTEGER DEFAULT 0  -- 1 = full rebuild required (schema migration)
);
```

---

## 3. Index Lifecycle

### 3.1 Write-Time Indexing

When an item is stored locally (via publish or replication), the node decrypts it and indexes the content.

**Text extraction rules.** The indexable text depends on the item content structure:

| Content shape | `name` | `summary` | `content_text` | `tags_text` |
|---------------|--------|-----------|-----------------|-------------|
| Memory item (`memory:*` item_type, has `name` field) | `content.name` | `content.summary` or `""` | `content.content` | `content.tags` joined by spaces, or `""` |
| Structured content (has `text` field) | `""` | `""` | `content.text` | `metadata.tags` joined by spaces, or `""` |
| Plain string content | `""` | `""` | `content` (raw string) | `""` |
| Other JSON content | `""` | `""` | JSON-serialised `content` (full text) | `metadata.tags` joined by spaces, or `""` |

The extraction rules are applied in order: first match wins. If `content` is null or the item has no decryptable content (e.g., system items), it is not indexed.

**Indexing steps (synchronous):**

1. Decrypt item using channel PSK (per ecies-envelope-encryption.md S5.3)
2. Parse decrypted JSON
3. Extract text fields per the table above
4. Insert row into `search_content`. If `item_id` already exists in `search_content` (UNIQUE constraint), UPDATE the existing row instead of INSERT. This handles re-indexing and content updates.
5. FTS5 trigger fires automatically, updating `search_fts`
6. Update `search_index_state.total_indexed` for the channel
7. Queue embedding generation (asynchronous, see S3.2)

**Replication arrival.** Items received from peers via Item-Push (realtime channels) or Item-Sync (batch channels) follow the same indexing path. The node decrypts with the channel PSK and indexes locally. If the PSK is not yet available (e.g., pending PSK-Exchange), the item is stored encrypted and indexed when the PSK arrives.

**Content update handling.** When an existing item is updated (same `item_id`, different content):

1. Update `search_content` row (triggers FTS5 update via trigger)
2. Recompute `content_hash` for the new content
3. If `content_hash` differs from `search_embedding_meta.content_hash`: set `status = "stale"`, queue re-embedding
4. If `content_hash` matches: no embedding update needed

**Deferred indexing for pending PSKs.** When items arrive for a channel whose PSK is not yet held locally:

1. Store the encrypted item as normal
2. Mark the item_id in a `pending_index` set (in-memory, keyed by channel_id)
3. When the PSK arrives (via PSK-Exchange), iterate the pending set and index each item
4. Clear the pending set for that channel

**Crash recovery.** The `pending_index` set is in-memory and lost on node restart. On startup, the node MUST scan for items in channels where the PSK is now held but no corresponding `search_content` row exists. This scan is bounded by `search_index_state.last_indexed_item_id` -- only items after the last indexed item need checking.

### 3.2 Embedding Generation

Embeddings are generated asynchronously after FTS5 indexing. The item is available for keyword search immediately; semantic search becomes available once the embedding is stored.

**Embedding pipeline:**

1. Construct embeddable text: concatenate `name + " " + summary + " " + content_text` (trimmed, collapsed whitespace)
2. Compute cache key: `SHA-256(embeddable_text)` as hex string
3. Check `search_embedding_meta` for existing entry with matching `content_hash`:
   - If `status = "complete"` and `content_hash` matches: skip (already embedded)
   - If no entry or `content_hash` differs: proceed
4. Insert or update `search_embedding_meta` with `status = "pending"`
5. POST to Ollama API:

```
POST http://localhost:11434/api/embeddings
Content-Type: application/json

{
  "model": "nomic-embed-text-v1.5",
  "prompt": "<embeddable_text>"
}
```

**Response:**
```json
{
  "embedding": [0.123, -0.456, ...]
}
```

6. Insert row into `search_vec_map` (item_id, channel_id), then insert embedding vector into `search_vec` at the corresponding rowid
7. Update `search_embedding_meta`: set `status = "complete"`, `generated_at = now()`
8. Update `search_index_state.total_embedded` for the channel

**Error handling:**

| Failure | Action |
|---------|--------|
| Ollama not running (connection refused) | Set `status = "failed"`, log warning. Item remains FTS5-searchable. |
| Ollama returns HTTP error (4xx/5xx) | Set `status = "failed"`, log error with status code. |
| Ollama returns malformed response (missing `embedding` field, wrong dimensions) | Set `status = "failed"`, log error with details. |
| Embedding dimensions != 768 | Reject. Set `status = "failed"`. Log dimension mismatch. |

Failed embeddings are retried by the backfill tool (S3.4). No automatic retry on write path to avoid blocking the write pipeline.

**Queue implementation.** Phase 1 uses a simple in-process FIFO queue (bounded, `[search] embedding_queue_size` items, default 1000). A single background worker dequeues items and calls Ollama sequentially. If the queue is full, new embedding requests are dropped (item remains FTS5-searchable, embedding is generated on next backfill). Phase 2 evaluates parallel workers and batch embedding APIs.

### 3.3 Index Rebuild

A full index rebuild re-indexes all items in a channel from scratch. This is a maintenance operation triggered by:

1. **Schema migration:** The `schema_version` in `search_index_state` does not match the current version. The node sets `needs_rebuild = 1` during migration.
2. **Manual reindex:** `POST /api/v1/channels/reindex` (WP8, post-Phase 1 MVP).
3. **Backfill tool:** `memory_backfill_embeddings` MCP tool (see S3.4).

**Rebuild process:**

1. Begin SQLite transaction
2. Delete all rows from `search_content` WHERE `channel_id = ?`
3. Delete all rows from `search_vec` WHERE `rowid IN (SELECT rowid FROM search_vec_map WHERE channel_id = ?)`, then delete matching rows from `search_vec_map`
4. Delete all rows from `search_embedding_meta` WHERE `channel_id = ?`
5. Reset `search_index_state` for the channel: `total_indexed = 0`, `total_embedded = 0`, `last_indexed_item_id = NULL`
6. Commit transaction
7. Iterate all non-tombstone items in the channel, ordered by `published_at ASC`:
   a. Decrypt item
   b. Extract text fields (S3.1 extraction rules)
   c. Insert into `search_content`
   d. Queue embedding generation
   e. Update `search_index_state.last_indexed_item_id` and `total_indexed` every 100 items (checkpoint)
8. Log completion: channel_id, items indexed, time elapsed

**Progress tracking.** The `last_indexed_item_id` checkpoint enables resumption if the rebuild is interrupted (node restart). On next startup, the node checks for channels with `needs_rebuild = 1` and resumes from `last_indexed_item_id`.

**Rebuild endpoint (WP8, post-MVP):**

```
POST /api/v1/channels/reindex

{
  "channel": "research-findings"
}
```

Response: `200` with `{"channel": "research-findings", "channel_id": "a1b2c3...", "status": "started", "items_to_index": 342}`. The reindex runs asynchronously. The caller can poll `search_index_state` for progress.

### 3.4 Backfill Tool

The `memory_backfill_embeddings` MCP tool rebuilds missing or stale embeddings without rebuilding the FTS5 index.

**Behaviour:**

1. Query `search_embedding_meta` WHERE `status IN ('pending', 'failed', 'stale')` AND `channel_id = ?` (or all channels if channel not specified)
2. For each row:
   a. Look up `search_content` for the item's text fields
   b. Recompute embeddable text and cache key
   c. Generate embedding via Ollama
   d. Insert/update `search_vec`
   e. Update `search_embedding_meta` status
3. Return: `{"backfilled": 42, "failed": 3, "skipped": 0}`

**Idempotent.** Running backfill multiple times is safe. Items with `status = "complete"` and matching `content_hash` are skipped.

### 3.5 Tombstone Handling

When a tombstone is received (local delete or replicated tombstone):

1. Delete the row from `search_content` WHERE `item_id = ?` (triggers FTS5 delete via trigger)
2. Delete from `search_vec` WHERE `rowid = (SELECT rowid FROM search_vec_map WHERE item_id = ?)`, then delete from `search_vec_map` WHERE `item_id = ?`
3. Delete the row from `search_embedding_meta` WHERE `item_id = ?`
4. Decrement `search_index_state.total_indexed` and `total_embedded`

**Invariant:** Tombstoned items MUST NOT appear in search results. The delete from `search_content` ensures FTS5 will never match the item. The delete from `search_vec` ensures semantic search will never match.

---

## 4. Query Processing

### 4.1 FTS5 Query

The search endpoint (`POST /api/v1/channels/search`, defined in channels-api.md S3.13) executes FTS5 queries against `search_fts`.

**Query sanitization** (per channels-api.md S3.13):

| Constraint | Limit | Error |
|------------|-------|-------|
| Maximum query length | 200 characters | `400 bad_request` |
| Maximum terms | 20 (split on whitespace) | `400 bad_request` |
| Minimum prefix length | 3 characters before `*` (reject `a*`, `ab*`) | `400 bad_request` |
| Empty query | Rejected | `400 bad_request` |
| Query timeout | 5 seconds | `500 query_timeout` |

**FTS5 special character handling.** Before passing the query to FTS5 MATCH, the node MUST escape or reject the following characters that have special meaning in FTS5 syntax:

| Character | Handling |
|-----------|----------|
| `"` (double quote) | Must be balanced (even count). Unbalanced quotes cause FTS5 syntax error. Reject with `400 bad_request` if unbalanced. |
| `(`, `)` | Must be balanced. Unbalanced parentheses cause FTS5 syntax error. Reject with `400 bad_request`. |
| `*` | Allowed only at end of token (prefix query). Reject `*` at start or middle of token. |
| `^` | Column filter prefix. Allowed only at start of token (e.g., `^name:vector`). Strip if found elsewhere. |
| `:` | Column filter separator. Allowed in column filter context (e.g., `name:vector`). Strip if bare. |

Parameterised MATCH (`WHERE search_fts MATCH ?1`) protects against SQL injection but does NOT protect against malformed FTS5 syntax. The application layer MUST validate FTS5 syntax before executing the query.

**FTS5 operators.** `AND`, `OR`, `NOT`, `NEAR` are permitted. They count towards the 20-term limit. `NEAR` requires at least two arguments (`NEAR(a b)` counts as 3 terms: `NEAR`, `a`, `b`). Column filters (`name:vector`) are permitted.

**SQL construction.** All queries MUST use parameterised statements. No string interpolation of query text into SQL.

```sql
-- FTS5 keyword search with BM25 scoring
SELECT
    sc.item_id,
    sc.channel_id,
    sc.item_type,
    sc.published_at,
    bm25(search_fts) AS fts_score
FROM search_fts
JOIN search_content sc ON search_fts.rowid = sc.rowid
WHERE search_fts MATCH ?1
  AND sc.channel_id = ?2
  AND sc.is_tombstone = 0
ORDER BY fts_score
LIMIT ?3;
```

**Performance note.** The JOIN between `search_fts` and `search_content` on `rowid` is an integer primary key lookup -- O(1) per match. FTS5 external content tables use the content table's rowid directly, so this join adds negligible overhead.

**Note on `bm25()` return values.** FTS5 `bm25()` returns negative values (lower is better). The node MUST negate and normalise to a 0-1 range before passing to the hybrid scorer. Normalisation: divide by the absolute value of the best (most negative) score in the result set. If only one result, its normalised score is 1.0.

**BM25 normalisation procedure:**

1. Execute FTS5 query, collecting all `(item_id, bm25_raw)` pairs
2. Find `best_raw = min(bm25_raw)` (most negative = best match)
3. If `best_raw == 0`: all normalised scores = 0 (no meaningful match)
4. For each result: `keyword_score = bm25_raw / best_raw` (yields 1.0 for best match, values in (0, 1] for others)

### 4.2 Semantic Query

Semantic search embeds the query text and finds the nearest vectors in `search_vec`.

**Query embedding:**

1. Embed the query string using the same model and parameters as item embedding (nomic-embed-text-v1.5 via Ollama)
2. If Ollama is unavailable: skip semantic search, return FTS5-only results (with `semantic_available: false` in response metadata)

**Vector search SQL:**

```sql
-- Cosine similarity search via sqlite-vec
-- Join through mapping table to recover item_id
SELECT
    svm.item_id,
    sv.distance
FROM search_vec sv
JOIN search_vec_map svm ON sv.rowid = svm.rowid
WHERE sv.embedding MATCH ?1     -- ?1 = query embedding vector
  AND k = ?2                     -- ?2 = limit (fetch more than final limit for hybrid merge)
ORDER BY sv.distance;
```

**Cosine similarity normalisation.** sqlite-vec returns cosine distance (0 = identical, 2 = opposite). Convert to similarity: `semantic_score = 1.0 - (distance / 2.0)`. This yields a 0-1 range where 1.0 is a perfect match.

**Channel filtering for semantic results.** sqlite-vec does not support JOIN or WHERE clauses beyond its built-in `MATCH` and `k`. The node MUST:

1. Fetch `k * 3` results from `search_vec` (over-fetch to account for channel filtering)
2. Look up `search_vec_map.channel_id` for each result
3. Filter to the target `channel_id`
4. If fewer than `limit` results remain after filtering, the result set is smaller than requested (acceptable)

### 4.3 Hybrid Scoring

The hybrid scorer combines FTS5 and semantic scores per-result using the dominant-signal formula defined in memory-model.md S7.1.

**Formula:**

```
score = dominant_weight * max(semantic, keyword) + (1 - dominant_weight) * min(semantic, keyword)
```

**Default `dominant_weight`: 0.7** (configurable via `config.toml [search] dominant_weight`, valid range 0.5-0.9).

**Behaviour:**

- The stronger signal leads at `dominant_weight` (70% by default). The weaker signal boosts at `1 - dominant_weight` (30%).
- This adapts per-result: a keyword-precise query that matches an item by name scores high on FTS5, and FTS5 leads. A conceptual query that matches semantically but not by exact keyword has semantic leading.
- If one signal is absent (item has no embedding, or FTS5 returned no match for this item):
  - `score = dominant_weight * present_signal + (1 - dominant_weight) * 0`
  - Simplified: `score = dominant_weight * present_signal`
- If both signals are 0 for an item: the item is excluded from results.
- If embeddings are globally unavailable (Ollama down): all results score `keyword_score * dominant_weight`. The relative ranking is preserved (BM25 ordering).

**Merge procedure:**

1. Collect FTS5 results: `{item_id -> keyword_score}` (normalised 0-1)
2. Collect semantic results: `{item_id -> semantic_score}` (normalised 0-1)
3. Union all item_ids from both sets
4. For each item_id:
   - `kw = keyword_scores.get(item_id, 0.0)`
   - `sem = semantic_scores.get(item_id, 0.0)`
   - `score = dominant_weight * max(sem, kw) + (1 - dominant_weight) * min(sem, kw)`
5. Sort by `score` descending
6. Tiebreak: `published_at` descending (most recent first)
7. Apply `limit`

### 4.4 Channel Scoping

**Mandatory constraint.** All search queries MUST include `channel_id` as a WHERE clause. This is enforced at two levels:

1. **API level:** The search endpoint requires `channel` (name or channel_id). Requests without `channel` return `400 bad_request` (channels-api.md S3.13).
2. **Query level:** FTS5 queries join on `search_content.channel_id = ?`. Semantic queries post-filter by `channel_id` (S4.2).

**No cross-channel search in Phase 1.** A single search request queries exactly one channel. The SDK does not provide a multi-channel search method.

**Phase 3 cross-channel search.** Cross-channel queries across all subscribed channels. Requires careful access control: the node must verify the caller holds the PSK for each channel in the result set. Specified when this phase is designed.

### 4.5 Result Filtering

The search endpoint supports two optional filters:

**Type filter (`types`):**

```sql
AND sc.item_type IN ('memory:learning', 'memory:entity')
```

If `types` is omitted, all item types are returned. The `types` array is parameterised (one `?` per type, not string-interpolated).

**Time filter (`since`):**

```sql
AND sc.published_at > ?
```

ISO 8601 timestamp. Only items published after `since` are returned.

### 4.6 Result Ordering and Limits

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| Primary sort | hybrid score descending | -- | Highest relevance first |
| Tiebreak | `published_at` descending | -- | Most recent first among equal scores |
| `limit` | 20 | 1-100 | Maximum results returned |

**Over-fetching.** The node should fetch more candidates than `limit` from each index (recommended: `limit * 3` from FTS5, `limit * 3` from semantic) to ensure the hybrid merge has sufficient candidates after filtering. (3x is a heuristic balancing recall against query cost; adjust if post-filter hit rates are consistently below 33%.)

### 4.7 Response Format

The search response format is defined in channels-api.md S3.13. The `score` field in each result is the hybrid score (0-1) computed per S4.3. When embeddings are unavailable, the score is the FTS5 BM25 score scaled by `dominant_weight`.

```json
{
  "channel": "research-findings",
  "results": [
    {
      "item_id": "ci_01JARC9B0ETZFGV8QKM3DVNX5P",
      "content": { "type": "insight", "text": "Vector search alone..." },
      "metadata": { "tags": ["research", "memory"] },
      "item_type": "message",
      "parent_id": null,
      "author": "cordelia_pk1...",
      "published_at": "2026-03-10T19:36:00Z",
      "signature_valid": true,
      "score": 0.85
    }
  ],
  "total": 1,
  "semantic_available": true
}
```

**`semantic_available`**: `true` if the semantic search index was available for this query, `false` if search fell back to FTS5-only (Ollama unavailable or `embedding_enabled = false`). When `false`, scores reflect BM25 keyword matching only.

---

## 5. Privacy and Security

Search indexes contain decrypted plaintext. Their security properties are defined by the node's local trust boundary. This section consolidates the privacy constraints from memory-model.md S11.2 and review-privacy.md.

### 5.1 Trust Boundary

| Observer | Sees | Cannot See |
|----------|------|------------|
| Local node process | FTS5 index, embedding vectors, decrypted content, all metadata | -- |
| Local filesystem (mode 0600 on cordelia.db) | Same as node process (if file is read) | -- |
| Relay / peer (network) | Encrypted items only (ciphertext, item metadata envelope) | FTS5 index, embeddings, decrypted content |
| Paired device (same identity) | Its own locally-built indexes (built from same decrypted items) | This node's index files (indexes are never replicated) |

A compromised local node exposes the FTS5/vec index. This is the same threat boundary as PSK compromise (the node holds PSKs). Mitigating local node compromise is out of scope for the search subsystem.

### 5.2 Database File Permissions

The SQLite database (`~/.cordelia/cordelia.db`) MUST be mode `0600` (owner read/write only). This is set at `cordelia init` (operations.md S2.3) and verified at node startup. If permissions are more permissive than `0600`, the node logs a warning but does not refuse to start (to avoid breaking existing installations).

### 5.3 SQL Injection Prevention

All FTS5 MATCH queries and all WHERE clause parameters MUST use SQLite parameterised statements (`?1`, `?2`, etc.). String interpolation of user-provided query text into SQL is prohibited.

**Specific risks mitigated:**
- FTS5 MATCH injection: a malicious query could exploit FTS5 syntax to extract data from other columns or trigger excessive computation. Parameterised MATCH prevents this.
- Channel ID bypass: interpolating `channel_id` could allow cross-channel queries. Parameterisation binds `channel_id` as a value, not a SQL fragment.

### 5.4 Cross-Channel Isolation

FTS5 and sqlite-vec indexes span all subscribed channels in a single SQLite database. The search endpoint MUST enforce `channel_id` as a mandatory parameter. Without this enforcement, a query could return items from channels the caller did not intend to search (all items are decrypted and indexed together).

Phase 1 does not support cross-channel search. Phase 3 adds explicit cross-channel search with per-channel PSK verification.

### 5.5 Index Content Sensitivity

Indexes contain the same plaintext as decrypted items. For memory channels (`__personal`), this includes:
- Entity names, relationships, preferences
- Learning content, decision rationale
- Session summaries, project context
- Tags, domain classifications

Operators deploying Cordelia should be aware that the local SQLite database is the single point of plaintext exposure. Disk encryption (e.g., FileVault, LUKS) provides defence-in-depth.

### 5.6 PSK Rotation Impact

When a channel's PSK is rotated (channels-api.md §3.8), existing search indexes remain valid. The indexes contain decrypted plaintext derived from items encrypted with the old PSK. New items arrive encrypted with the new PSK and are indexed normally. No index rebuild is required on PSK rotation.

Items encrypted with the old PSK that the node has already decrypted and indexed are unaffected. Items encrypted with the old PSK that the node has NOT yet decrypted cannot be indexed until the node obtains the old PSK (if applicable) or the item is re-published with the new PSK.

---

## 6. Performance

### 6.1 Targets

| Operation | Target | Measured Against |
|-----------|--------|-----------------|
| FTS5 keyword search | < 50ms | Channel with 1000 items, 20-result limit |
| Semantic search (sqlite-vec) | < 50ms | Channel with 1000 items, 60-candidate k |
| Hybrid merge + sort | < 10ms | 120 candidates (60 FTS5 + 60 semantic) |
| Total search latency | < 100ms | End-to-end, FTS5 + semantic + merge |
| FTS5 indexing (per item) | < 5ms | Single item insert into search_content + FTS5 trigger |
| Embedding generation (per item) | ~50ms | Local Ollama, nomic-embed-text-v1.5, ~500 token input |
| Index rebuild (1000 items) | < 10s | FTS5 only (embeddings queued async) |

### 6.2 Query Timeout

FTS5 queries are bounded by a 5-second timeout (channels-api.md S3.13). If the query exceeds this limit, the node returns `500` with error code `query_timeout`. This prevents pathological FTS5 queries (e.g., very broad prefix matches) from blocking the API.

Implementation: use `sqlite3_progress_handler()` with a callback that checks elapsed time. Set the check interval to every 1000 VM instructions.

### 6.3 Index Size Estimates

| Component | Per-Item Size | 1000 Items | 10000 Items |
|-----------|---------------|------------|-------------|
| `search_content` row | ~500 bytes avg (text fields) | ~500 KB | ~5 MB |
| FTS5 inverted index | ~1-2x content size | ~0.5-1 MB | ~5-10 MB |
| `search_vec` row | 3072 bytes (768 * 4-byte float) | ~3 MB | ~30 MB |
| `search_vec_map` row | ~100 bytes | ~100 KB | ~1 MB |
| `search_embedding_meta` row | ~200 bytes | ~200 KB | ~2 MB |
| **Total** | | **~4-5 MB** | **~40-47 MB** |

The dominant cost is the vector table. For channels with many items, consider the `[search] embedding_enabled` config option (S7) to disable semantic search and eliminate the vector storage overhead.

### 6.4 Embedding Queue Backpressure

The embedding queue (S3.2) is bounded at 1000 items. If the queue is full:
- New embedding requests are silently dropped
- The item remains FTS5-searchable
- A warning is logged: `"embedding queue full, item {item_id} deferred to backfill"`
- The `search_embedding_meta` entry remains at `status = "pending"`
- The next backfill run picks up the pending item

This prevents embedding generation from consuming unbounded memory during bulk imports or large replication syncs.

### 6.5 Index Health Monitoring

The `search_index_state` table (§2.5) provides per-channel monitoring data. Operators should alert on:

| Condition | Indicator | Action |
|-----------|-----------|--------|
| Embedding backlog | `total_indexed - total_embedded > 100` | Check Ollama availability, run `memory_backfill_embeddings` |
| Index rebuild needed | `needs_rebuild = 1` | Automatic on next startup; manual via reindex endpoint (post-MVP) |
| Stale index | `last_indexed_at` older than `replication.sync_interval_realtime_secs * 10` | Investigate write pipeline |

---

## 7. Configuration

All search configuration lives under the `[search]` section in `config.toml` (`~/.cordelia/config.toml`).

```toml
[search]
# Hybrid scoring weight for the dominant signal.
# Higher values give more weight to the stronger signal (keyword or semantic).
# Default: 0.7. Range: 0.5-0.9.
dominant_weight = 0.7

# Embedding model identifier (must be available via Ollama).
embedding_model = "nomic-embed-text-v1.5"

# Ollama API endpoint for embedding generation.
ollama_url = "http://localhost:11434"

# Enable/disable semantic search. When false, search uses FTS5 only.
# Set to false on machines without Ollama or GPU.
# Default: true.
embedding_enabled = true

# Maximum items in the embedding generation queue.
# Default: 1000.
embedding_queue_size = 1000
```

| Key | Type | Default | Range / Valid Values | Description |
|-----|------|---------|---------------------|-------------|
| `dominant_weight` | float | `0.7` | `0.5` - `0.9` | Weight for the dominant (stronger) signal in hybrid scoring |
| `embedding_model` | string | `"nomic-embed-text-v1.5"` | Any Ollama model name | Model used for embedding generation |
| `ollama_url` | string | `"http://localhost:11434"` | URL | Ollama API base URL |
| `embedding_enabled` | boolean | `true` | `true` / `false` | Enable semantic search and embedding generation |
| `embedding_queue_size` | integer | `1000` | `100` - `10000` | Maximum pending embedding requests |

**Validation at startup:**
- `dominant_weight` outside `[0.5, 0.9]`: node logs an error and refuses to start (per configuration.md §5.2)
- `embedding_model` not available in Ollama at startup: log warning, set `embedding_enabled = false` at runtime. Re-checked on each embedding request.
- `ollama_url` not reachable: log warning, set `embedding_enabled = false` at runtime (re-checked periodically)

---

## 8. Phase Boundaries

### 8.1 Phase 1 (Encrypted Pub/Sub MVP)

Delivered:
- FTS5 full-text search with BM25 scoring
- sqlite-vec semantic search with nomic-embed-text-v1.5 via local Ollama
- Dominant-signal hybrid scoring (configurable weight)
- Single-channel search only (channel_id mandatory)
- Synchronous FTS5 indexing on write
- Asynchronous embedding generation with in-process queue
- Graceful degradation to FTS5-only when Ollama is unavailable
- Query sanitization (length, term count, prefix minimum, timeout)
- Parameterised SQL (no string interpolation)
- Tombstone removal from indexes
- `memory_backfill_embeddings` MCP tool for embedding repair
- `search_index_state` table for index health monitoring

Not delivered in Phase 1:
- `POST /api/v1/channels/reindex` endpoint (WP8, post-MVP)
- Cross-channel search
- Domain-aware retrieval boosting
- Cloud embedding fallback
- Batch embedding API

### 8.2 Phase 2 (Provider Integration)

Additions:
- **Domain-aware search boosting** (memory-model.md S7.2): retrieval boost signal based on memory domain. Architectural queries weight values-domain items higher; debugging queries weight procedural items higher. Boosting, not filtering.
- **Cloud embedding API fallback:** When local Ollama is unavailable and `[search] cloud_embedding_url` is configured, use a cloud embedding API. Requires network access and API key. Privacy trade-off: query text is sent to the cloud provider. Must be opt-in.
- **Domain-specialised embeddings evaluation:** Different embedding models for values vs procedural vs interrupt domains. Requires evaluation against retrieval quality benchmarks.
- **`POST /api/v1/channels/reindex` endpoint** (WP8): on-demand index rebuild per channel.
- **Batch embedding API:** Ollama batch endpoint for bulk embedding generation (faster backfill).

### 8.3 Phase 3 (Network Growth)

Additions:
- **Cross-channel search:** Query across all subscribed channels. The node verifies PSK access for each channel in the result set. New SDK method: `c.searchAll(query, options)`.
- **Knowledge graph overlay search:** Graph-based traversal of entity relationships across channels. Requires a graph index (separate from FTS5/vec).
- **CJK/multilingual tokenizer:** Evaluate `trigram` tokenizer or ICU tokenizer for non-Latin scripts.

---

## 9. Test Vectors

### 9.1 BM25 Normalisation

Given FTS5 raw scores for three results:

```
item_a: bm25_raw = -3.5  (best match)
item_b: bm25_raw = -2.1
item_c: bm25_raw = -0.7
```

Normalised (S4.1 procedure):
```
best_raw = -3.5
item_a: keyword_score = -3.5 / -3.5 = 1.000
item_b: keyword_score = -2.1 / -3.5 = 0.600
item_c: keyword_score = -0.7 / -3.5 = 0.200
```

### 9.2 Cosine Similarity Normalisation

Given sqlite-vec cosine distances:

```
item_a: distance = 0.15
item_b: distance = 0.42
item_c: distance = 1.10
```

Normalised (S4.2):
```
item_a: semantic_score = 1.0 - (0.15 / 2.0) = 0.925
item_b: semantic_score = 1.0 - (0.42 / 2.0) = 0.790
item_c: semantic_score = 1.0 - (1.10 / 2.0) = 0.450
```

### 9.3 Hybrid Scoring

Given `dominant_weight = 0.7`:

**Case 1: Both signals present**
```
item_a: keyword = 1.000, semantic = 0.925
  max = 1.000 (keyword), min = 0.925 (semantic)
  score = 0.7 * 1.000 + 0.3 * 0.925 = 0.978

item_b: keyword = 0.200, semantic = 0.790
  max = 0.790 (semantic), min = 0.200 (keyword)
  score = 0.7 * 0.790 + 0.3 * 0.200 = 0.613
```

**Case 2: FTS5-only (no embedding)**
```
item_c: keyword = 0.600, semantic = 0.0
  max = 0.600, min = 0.0
  score = 0.7 * 0.600 + 0.3 * 0.0 = 0.420
```

**Case 3: Semantic-only (no FTS5 match)**
```
item_d: keyword = 0.0, semantic = 0.450
  max = 0.450, min = 0.0
  score = 0.7 * 0.450 + 0.3 * 0.0 = 0.315
```

### 9.4 Query Sanitization

| Input | Result | Reason |
|-------|--------|--------|
| `"vector embeddings"` | Accept | 2 terms, 15 chars |
| `""` | Reject 400 | Empty query |
| `"a*"` | Reject 400 | Prefix too short (1 char before *) |
| `"ab*"` | Reject 400 | Prefix too short (2 chars before *) |
| `"vec*"` | Accept | Prefix ok (3 chars before *) |
| 201-char string | Reject 400 | Exceeds 200-char limit |
| `"a b c d e f g h i j k l m n o p q r s t u"` | Reject 400 | 21 terms exceeds 20-term limit |
| `"vector AND embeddings NOT retrieval"` | Accept | 5 terms (operators count as terms) |

---

## 10. Glossary Cross-References

Terms defined in specs/glossary.md that are used in this specification:

- **Channel**: Encrypted topic for publishing items (named, DM, or group)
- **PSK (Pre-Shared Key)**: Per-channel AES-256-GCM key used to encrypt all items
- **Item**: A published unit of content, encrypted with channel PSK
- **Tombstone**: Soft-delete marker (`is_tombstone=true`), propagated via replication
- **Personal channel**: The `__personal` system channel for private storage
- **Node**: A running Cordelia process with cryptographic identity and persistent storage (SQLite)
- **Subscriber**: An entity subscribed to a channel (holds the PSK)
- **Embedding**: A dense vector representation of text content, produced by a language model (e.g., nomic-embed-text-v1.5). Used for semantic similarity search.
- **FTS5**: SQLite full-text search extension. Provides keyword-precise matching with BM25 relevance scoring.
- **BM25**: Best Match 25, a TF-IDF-family ranking function used by FTS5 to score keyword relevance.

---

*Draft: 2026-03-12. Implementation-ready search specification -- complements channels-api.md S3.13 and memory-model.md S7.*
