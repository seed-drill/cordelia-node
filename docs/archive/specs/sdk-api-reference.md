# SDK API Reference

**Status**: Draft
**Author**: Russell Wing, Claude (Opus 4.6)
**Date**: 2026-03-10
**Scope**: Phase 1 (Encrypted Pub/Sub MVP)
**Implements**: WP6 (SDK Package)
**Package**: `@seeddrill/cordelia`
**Depends on**: specs/channels-api.md, specs/ecies-envelope-encryption.md

---

## 1. Overview

The Cordelia SDK is a TypeScript client for the node REST API. It provides a developer-friendly interface for encrypted pub/sub, DMs, group conversations, and search. No crypto code -- the node handles all encryption.

### 1.1 Design Principles

1. **Zero config.** `new Cordelia()` connects to the local node. No URLs, no keys, no setup.
2. **No crypto in the SDK.** The node is the encryption boundary. The SDK sends and receives plaintext.
3. **Channel names, not IDs.** Developers work with human-readable names. IDs are internal.
4. **Thin client.** The SDK is an HTTP client with types. Business logic lives in the node.
5. **Developer terminology.** `realtime`/`batch`, not `chatty`/`taciturn`. `subscribe`/`publish`/`listen`, not `groups/create`/`l2/write`/`groups/items`.

### 1.2 Installation

```bash
npm install @seeddrill/cordelia
```

### 1.3 Quick Start

```typescript
import { Cordelia } from '@seeddrill/cordelia'

const c = new Cordelia()

await c.subscribe('research-findings')
await c.publish('research-findings', { type: 'insight', text: 'Vector search alone is insufficient...' })
const items = await c.listen('research-findings')
```

All data is encrypted end-to-end. All data is replicated to peers. Zero config.

### 1.4 Logging and Privacy

Channel IDs are implementation details. Applications should use channel names in user-facing logs and error messages. Do not log raw `channel_id`, `author_id` (Bech32 keys), or bearer tokens in production. The SDK marks these fields as sensitive in TypeScript JSDoc annotations.

---

## 2. Constructor

```typescript
const c = new Cordelia(opts?: CordeliaOptions)
```

### CordeliaOptions

```typescript
interface CordeliaOptions {
  /** Node REST API URL. Default: "http://localhost:9473" */
  nodeUrl?: string

  /** Bearer token for authentication. Default: read from ~/.cordelia/node-token */
  token?: string

  /** Poll interval for realtime channels (ms). Default: 2000 */
  realtimePollMs?: number

  /** Poll interval for batch channels (ms). Default: 30000 */
  batchPollMs?: number
}
```

**Default behaviour:**

1. `nodeUrl` defaults to `http://localhost:9473`
2. `token` defaults to reading `~/.cordelia/node-token` (file contains hex-encoded 32-byte token)
3. If token file does not exist, constructor throws `CordeliaError('NODE_NOT_INITIALIZED')`

**Examples:**

```typescript
// Default: local node, token from file
const c = new Cordelia()

// Remote node with explicit token
const c = new Cordelia({
  nodeUrl: 'http://192.168.1.100:9473',
  token: 'a1b2c3d4...'
})

// Agent with credential bundle
const c = new Cordelia({
  token: process.env.CORDELIA_TOKEN
})
```

---

## 3. Channels

### 3.1 subscribe()

Join or create an encrypted channel.

```typescript
async subscribe(channel: string, opts?: SubscribeOptions): Promise<ChannelHandle>
```

```typescript
interface SubscribeOptions {
  /** Replication mode. Default: "realtime" */
  mode?: 'realtime' | 'batch'

  /** Access policy. Default: "open" */
  access?: 'open' | 'invite_only'
}

interface ChannelHandle {
  /** Channel name */
  channel: string

  /** Internal channel ID (hex SHA-256) */
  channelId: string

  /** Whether this call created the channel */
  isNew: boolean

  /** Caller's role */
  role: 'owner' | 'admin' | 'member'

  /** Replication mode */
  mode: 'realtime' | 'batch'

  /** Access policy */
  access: 'open' | 'invite_only'

  /** Channel creation timestamp (ISO 8601) */
  createdAt: string
}
```

**Examples:**

```typescript
// Create or join a realtime channel
const ch = await c.subscribe('research-findings')
// ch.isNew === true (if first subscriber)
// ch.role === 'owner'

// Join in batch mode
const archive = await c.subscribe('paper-archive', { mode: 'batch' })

// Private channel
const internal = await c.subscribe('board-updates', { access: 'invite_only' })
```

**Maps to:** `POST /api/v1/channels/subscribe`

**Errors:**
- `CordeliaError('INVALID_CHANNEL_NAME')` -- name violates RFC 1035 rules
- `CordeliaError('NOT_AUTHORIZED')` -- invite_only channel, caller not invited
- `CordeliaError('NODE_UNREACHABLE')` -- cannot connect to node

---

### 3.2 publish()

Publish content to a channel. Content is encrypted by the node.

```typescript
async publish(channel: string, content: any, opts?: PublishOptions): Promise<PublishResult>
```

```typescript
interface PublishOptions {
  /** Application metadata (encrypted alongside content) */
  metadata?: Record<string, any>

  /** Content type hint. Default: "message". Also accepts "event" and "state".
   *  Stored in plaintext metadata for filtering without decryption.
   *  Node-internal types ("kv", "psk_envelope", "attestation", "descriptor") are rejected. */
  itemType?: 'message' | 'event' | 'state'

  /** Parent item ID for threading/replies */
  parentId?: string
}

interface PublishResult {
  /** Unique item ID */
  itemId: string

  /** Channel name or ID */
  channel: string

  /** Server timestamp */
  publishedAt: string

  /** Author public key (Bech32) */
  author: string

  /** Item type as stored */
  itemType: string
}
```

**Examples:**

```typescript
// Publish structured data
const result = await c.publish('research-findings', {
  type: 'insight',
  text: 'Vector search alone is insufficient for agent memory retrieval'
})

// Publish with metadata and item type
await c.publish('alerts', {
  level: 'warning',
  message: 'Replication lag exceeds 30s'
}, {
  metadata: { tags: ['ops', 'replication'], priority: 'high' },
  itemType: 'event'
})

// Threaded reply
await c.publish('engineering', { text: 'Agreed, +1' }, {
  parentId: 'ci_a1b2c3d4e5f6'
})

// Publish to a DM or group (use channel ID)
await c.publish(dm.channelId, { text: 'Hey, thoughts on the pivot?' })
```

**Maps to:** `POST /api/v1/channels/publish`

**Errors:**
- `CordeliaError('CHANNEL_NOT_FOUND')` -- not subscribed to this channel
- `CordeliaError('NOT_AUTHORIZED')` -- not a member
- `CordeliaError('PAYLOAD_TOO_LARGE')` -- content exceeds 256KB

---

### 3.3 listen()

Retrieve items from a channel. Returns items published since the given cursor.

```typescript
async listen(channel: string, opts?: ListenOptions): Promise<ListenResult>
```

```typescript
interface ListenOptions {
  /** Return items published after this timestamp. */
  since?: string

  /** Maximum items to return (1-500). Default: 50 */
  limit?: number
}

interface ListenResult {
  /** Decrypted items, ordered by published_at ASC */
  items: Item[]

  /** Cursor for next poll (pass as `since` in next call) */
  cursor: string

  /** Whether more items exist beyond the limit */
  hasMore: boolean
}

interface Item {
  /** Unique item ID */
  itemId: string

  /** Decrypted content (as published) */
  content: any

  /** Application metadata (as published) */
  metadata?: Record<string, any>

  /** Content type hint (e.g. "message", "event", "state") */
  itemType: string

  /** Parent item ID (if threaded reply) */
  parentId?: string

  /** Author public key (Bech32) */
  author: string

  /** Server timestamp */
  publishedAt: string

  /** Whether the author's signature verified */
  signatureValid: boolean
}
```

**Examples:**

```typescript
// Get latest items
const result = await c.listen('research-findings')

// Poll for new items (use cursor from previous call)
const next = await c.listen('research-findings', { since: result.cursor })

// Paginate through history
let cursor: string | undefined
do {
  const page = await c.listen('research-findings', { since: cursor, limit: 100 })
  for (const item of page.items) {
    console.log(item.content)
  }
  cursor = page.hasMore ? page.cursor : undefined
} while (cursor)
```

**Maps to:** `POST /api/v1/channels/listen`

**Errors:**
- `CordeliaError('CHANNEL_NOT_FOUND')`
- `CordeliaError('NOT_AUTHORIZED')`

---

### 3.4 unsubscribe()

Leave a channel. Deletes the local PSK.

```typescript
async unsubscribe(channel: string): Promise<void>
```

**Example:**

```typescript
await c.unsubscribe('research-findings')
```

**Maps to:** `POST /api/v1/channels/unsubscribe`

---

### 3.5 channels()

List channels the caller is subscribed to.

```typescript
async channels(): Promise<ChannelInfo[]>
```

```typescript
interface ChannelInfo {
  /** Channel name */
  channel: string

  /** Internal channel ID */
  channelId: string

  /** Caller's role */
  role: 'owner' | 'admin' | 'member'

  /** Replication mode */
  mode: 'realtime' | 'batch'

  /** Access policy */
  access: 'open' | 'invite_only'

  /** Number of items in channel (local count) */
  itemCount: number

  /** Timestamp of most recent item */
  lastActivity: string | null

  /** Channel creation timestamp */
  createdAt: string
}
```

**Example:**

```typescript
const channels = await c.channels()
for (const ch of channels) {
  console.log(`${ch.channel}: ${ch.itemCount} items, last active ${ch.lastActivity}`)
}
```

**Maps to:** `POST /api/v1/channels/list`

**Notes:** Returns named channels only. Use `c.dms()` and `c.groups()` for DMs and group conversations.

---

### 3.6 info()

Check if a channel exists without subscribing.

```typescript
async info(channel: string): Promise<ChannelDetails>
```

```typescript
interface ChannelDetails {
  /** Channel name */
  channel: string

  /** Internal channel ID (always returned, deterministic from name) */
  channelId: string

  /** Whether the channel exists */
  exists: boolean

  /** Replication mode (if exists) */
  mode?: 'realtime' | 'batch'

  /** Access policy (if exists) */
  access?: 'open' | 'invite_only'

  /** Owner public key (if exists) */
  owner?: string

  /** Number of members (if exists) */
  memberCount?: number
}
```

**Maps to:** `POST /api/v1/channels/info`

---

### 3.7 deleteItem()

Delete (tombstone) an item from a channel.

```typescript
async deleteItem(channel: string, itemId: string): Promise<void>
```

**Example:**

```typescript
await c.deleteItem('research-findings', 'ci_a1b2c3d4e5f6')
```

**Maps to:** `POST /api/v1/channels/delete-item`

**Errors:**
- `CordeliaError('NOT_AUTHORIZED')` -- not the item author or channel owner/admin

---

### 3.8 rotatePsk()

Manually rotate a channel's PSK. Use when key compromise is suspected without a member removal trigger.

```typescript
async rotatePsk(channel: string): Promise<RotateResult>
```

```typescript
interface RotateResult {
  /** New key version after rotation */
  newKeyVersion: number

  /** Number of members who received the new PSK envelope */
  membersNotified: number
}
```

**Example:**

```typescript
await c.rotatePsk('research-findings')
```

**Maps to:** `POST /api/v1/channels/rotate-psk`

**Errors:**
- `CordeliaError('NOT_AUTHORIZED', { context: 'not_owner' })` -- only the channel owner can rotate
- `CordeliaError('CHANNEL_NOT_FOUND')`

---

## 4. Direct Messages

### 4.1 dm()

Create or connect to a bilateral DM channel. Channel ID is derived deterministically from both public keys.

```typescript
async dm(peer: string): Promise<DMHandle>
```

```typescript
interface DMHandle {
  /** DM channel ID (dm_<hash>) */
  channelId: string

  /** Peer's public key (Bech32) */
  peer: string

  /** Whether this call created the DM */
  isNew: boolean

  /** Send a message */
  send(content: any, opts?: PublishOptions): Promise<PublishResult>

  /** Receive messages */
  listen(opts?: ListenOptions): Promise<ListenResult>
}
```

**Examples:**

```typescript
// Open a DM by public key
const dm = await c.dm('cordelia_pk1...')

// Send a message
await dm.send({ text: 'Hey, thoughts on the pivot?' })

// Receive messages
const msgs = await dm.listen()
for (const msg of msgs.items) {
  console.log(`${msg.author}: ${msg.content.text}`)
}

// DM with an entity by name (if resolvable)
const dm = await c.dm('bob')
```

**Maps to:** `POST /api/v1/channels/dm` (create), then `publish`/`listen` on the returned `channelId`

**Notes:**
- DMs are always realtime and invite_only
- Membership is immutable (exactly two entities)
- Both parties independently derive the same channel ID

---

### 4.2 dms()

List active DM channels.

```typescript
async dms(): Promise<DMInfo[]>
```

**Maps to:** `POST /api/v1/channels/list-dms`

```typescript
interface DMInfo {
  /** DM channel ID */
  channelId: string

  /** Peer's public key */
  peer: string

  /** Item count */
  itemCount: number

  /** Last activity */
  lastActivity: string | null
}
```

---

## 5. Group Conversations

### 5.1 group()

Create a group conversation with mutable membership.

```typescript
async group(members: string[], opts?: GroupOptions): Promise<GroupHandle>
```

```typescript
interface GroupOptions {
  /** Human-readable label (not globally unique) */
  name?: string
}

interface GroupHandle {
  /** Group channel ID (grp_<uuid>) */
  channelId: string

  /** Group label */
  name?: string

  /** Number of members */
  memberCount: number

  /** Whether this call created the group */
  isNew: boolean

  /** Send a message */
  send(content: any, opts?: PublishOptions): Promise<PublishResult>

  /** Receive messages */
  listen(opts?: ListenOptions): Promise<ListenResult>

  /** Invite a new member (PSK distributed via ECIES) */
  invite(member: string): Promise<void>

  /** Remove a member (triggers PSK rotation) */
  remove(member: string): Promise<void>
}
```

**Examples:**

```typescript
// Create a group conversation
const team = await c.group(['cordelia_pk1...', 'cordelia_pk1...'], { name: 'project-x' })

// Send to the group
await team.send({ type: 'update', text: 'Sprint review at 3pm' })

// Invite someone
await team.invite('cordelia_pk1...')

// Remove someone (PSK rotated automatically)
await team.remove('cordelia_pk1...')
```

**Maps to:** `POST /api/v1/channels/group` (create), `group/invite`, `group/remove`, then `publish`/`listen` on the returned `channelId`

---

### 5.2 groups()

List group conversations.

```typescript
async groups(): Promise<GroupInfo[]>
```

**Maps to:** `POST /api/v1/channels/list-groups`

```typescript
interface GroupInfo {
  /** Group channel ID */
  channelId: string

  /** Group label */
  name?: string

  /** Number of members */
  memberCount: number

  /** Item count */
  itemCount: number

  /** Last activity */
  lastActivity: string | null
}
```

---

## 6. Search

### 6.1 search()

Full-text search within a channel (FTS5 BM25).

```typescript
async search(channel: string, query: string, options?: SearchOptions): Promise<SearchResult>
```

```typescript
interface SearchOptions {
  /** Maximum results (1-100, default 20) */
  limit?: number

  /** Filter by item_type (e.g., ['memory:learning', 'memory:entity']) */
  types?: string[]

  /** Only return items published after this ISO 8601 timestamp */
  since?: string
}
```

```typescript
interface SearchResult {
  /** Channel searched */
  channel: string

  /** Matching items with relevance scores */
  results: SearchHit[]

  /** Total matches */
  total: number
}

interface SearchHit extends Item {
  /** BM25 relevance score (0-1) */
  score: number
}
```

**Examples:**

```typescript
const results = await c.search('research-findings', 'vector embeddings')
for (const hit of results.results) {
  console.log(`[${hit.score.toFixed(2)}] ${hit.content.text}`)
}

// Search with filters
const learnings = await c.search('__personal', 'pairing protocol', {
  types: ['memory:learning'],
  since: '2026-03-01T00:00:00Z',
  limit: 10
})

// Search a DM or group by channel ID
const dmResults = await c.search(dm.channelId, 'pivot')
```

**Maps to:** `POST /api/v1/channels/search`

---

## 7. Identity

### 7.1 identity()

Return the local node's identity.

```typescript
async identity(): Promise<Identity>
```

```typescript
interface Identity {
  /** Entity name (set during cordelia init) */
  entityId: string

  /** Ed25519 public key (Bech32).
   *  API field: ed25519_public_key -- custom mapping, not simple camelCase. */
  publicKey: string

  /** X25519 public key (Bech32).
   *  API field: x25519_public_key -- custom mapping, not simple camelCase. */
  encryptionKey: string

  /** Node's Ed25519 public key (Bech32: cordelia_pk1...) */
  nodeId: string

  /** Number of channels subscribed to */
  channelsSubscribed: number

  /** Number of connected peers */
  peersConnected: number
}
```

**Example:**

```typescript
const me = await c.identity()
console.log(`I am ${me.entityId} (${me.publicKey})`)

// Share your public key for DMs
console.log(`DM me at: ${me.publicKey}`)
```

**Maps to:** `POST /api/v1/channels/identity`

---

## 8. Error Handling

### 8.1 CordeliaError

All SDK errors are instances of `CordeliaError`:

```typescript
class CordeliaError extends Error {
  /** Machine-readable error code */
  code: CordeliaErrorCode

  /** HTTP status code from node (if applicable) */
  statusCode?: number

  /** Additional context for the error (e.g. NOT_AUTHORIZED reason) */
  context?: string
}

type CordeliaErrorCode =
  | 'NODE_NOT_INITIALIZED'    // ~/.cordelia/node-token not found
  | 'NODE_UNREACHABLE'        // Cannot connect to node
  | 'UNAUTHORIZED'            // Invalid bearer token
  | 'NOT_AUTHORIZED'          // Valid token, insufficient access
  | 'CHANNEL_NOT_FOUND'       // Channel does not exist
  | 'INVALID_CHANNEL_NAME'    // Name violates RFC 1035 rules
  | 'INVALID_KEY'             // Bech32 key decode failed
  | 'PAYLOAD_TOO_LARGE'       // Content exceeds 256KB
  | 'QUOTA_EXCEEDED'          // Storage quota exceeded (413 with quota fields, distinct from PAYLOAD_TOO_LARGE)
  | 'TIMEOUT'                 // Operation timed out (search query, connection)
  | 'CHANNEL_LIMIT_REACHED'   // Maximum channel subscription count reached
  | 'RATE_LIMITED'            // Too many requests (Phase 2+)
  | 'CONFLICT'                // Channel exists with different parameters
  | 'INTERNAL_ERROR'          // Node-side failure
```

**Examples:**

```typescript
try {
  await c.subscribe('research-findings')
} catch (e) {
  if (e instanceof CordeliaError) {
    switch (e.code) {
      case 'NODE_UNREACHABLE':
        console.log('Is your node running? Try: cordelia status')
        break
      case 'NOT_AUTHORIZED':
        // e.context is one of: 'invite_only' | 'not_a_member' | 'not_owner' | 'not_admin'
        console.log(`Access denied (${e.context}). Ask the owner for an invite.`)
        break
    }
  }
}
```

**NOT_AUTHORIZED context values:**

`NOT_AUTHORIZED` errors include a `context` string to distinguish the reason for denial:

| Context | Meaning |
|---------|---------|
| `'invite_only'` | Channel requires an invitation to subscribe |
| `'not_a_member'` | Caller is not a member of this channel |
| `'not_owner'` | Operation requires owner role |
| `'not_admin'` | Operation requires admin (or owner) role |

```typescript
// Example: checking context programmatically
if (e.code === 'NOT_AUTHORIZED' && e.context === 'invite_only') {
  // Request an invitation from the channel owner
}
```

---

## 9. Type Exports

All types are exported from the package root:

```typescript
import {
  // Main class
  Cordelia,
  CordeliaOptions,

  // Channel types
  ChannelHandle,
  ChannelInfo,
  ChannelDetails,
  SubscribeOptions,

  // Pub/sub types
  PublishOptions,
  PublishResult,
  ListenOptions,
  ListenResult,
  Item,
  RotateResult,

  // DM types
  DMHandle,
  DMInfo,

  // Group types
  GroupHandle,
  GroupInfo,
  GroupOptions,

  // Search types
  SearchResult,
  SearchHit,

  // Identity
  Identity,

  // Errors
  CordeliaError,
  CordeliaErrorCode,
} from '@seeddrill/cordelia'
```

---

## 10. Package Structure

```
@seeddrill/cordelia/
  src/
    index.ts          -- Cordelia class, public API
    client.ts         -- HTTP client (fetch-based, node REST API)
    types.ts          -- All TypeScript interfaces and types
    errors.ts         -- CordeliaError class
    config.ts         -- Default config, token file reading
  package.json
  tsconfig.json
  README.md           -- "Encrypted Pub/Sub in 5 Minutes"
  LICENSE             -- AGPL-3.0
```

### 10.1 Dependencies

Minimal. The SDK is a thin HTTP client.

| Dependency | Purpose | Required? |
|-----------|---------|-----------|
| (none) | `fetch()` is built into Node.js 18+ and all modern runtimes | -- |

**Zero runtime dependencies.** The SDK uses native `fetch()` (Node.js 18+, Deno, Bun, browsers). No axios, no node-fetch, no polyfills.

### 10.2 Build Targets

| Target | Format | Notes |
|--------|--------|-------|
| ESM | `dist/esm/index.js` | Default for modern bundlers |
| CJS | `dist/cjs/index.js` | Node.js require() compatibility |
| Types | `dist/types/index.d.ts` | TypeScript declarations |

### 10.3 Node.js Version

Minimum: Node.js 18 (LTS, native fetch). Tested on: 18, 20, 22.

---

## 11. SDK Internals

### 11.1 HTTP Client

The SDK uses a single internal HTTP client:

```typescript
// Internal -- not exported
class NodeClient {
  constructor(baseUrl: string, token: string)

  async post<T>(path: string, body: object): Promise<T>
}
```

All API calls go through `NodeClient.post()`, which:
1. Sets `Content-Type: application/json`
2. Sets `Authorization: Bearer <token>`
3. Serializes body as JSON (camelCase keys → snake_case for the API)
4. Parses response as JSON (snake_case keys → camelCase for TypeScript)
5. Throws `CordeliaError` on non-2xx responses

**Key convention:** The node REST API (channels-api.md) uses `snake_case` for all field names (`item_id`, `published_at`, `item_type`, `parent_id`, `signature_valid`). The SDK transforms these to idiomatic TypeScript `camelCase` (`itemId`, `publishedAt`, `itemType`, `parentId`, `signatureValid`). All interfaces in this spec use the SDK-facing camelCase form.

**Exception:** The identity endpoint uses custom field mapping (`ed25519_public_key` -> `publicKey`, `x25519_public_key` -> `encryptionKey`) that is not a simple case transformation.

### 11.2 Token Resolution

```typescript
// Internal -- not exported
function resolveToken(explicit?: string): string {
  if (explicit) return explicit
  if (process.env.CORDELIA_TOKEN) return process.env.CORDELIA_TOKEN

  const tokenPath = join(homedir(), '.cordelia', 'node-token')
  if (!existsSync(tokenPath)) throw new CordeliaError('NODE_NOT_INITIALIZED')
  return readFileSync(tokenPath, 'utf-8').trim()
}
```

Priority: explicit constructor arg > `CORDELIA_TOKEN` env var > `~/.cordelia/node-token` file.

### 11.3 Channel Name Validation

```typescript
// Internal -- not exported
const CHANNEL_NAME_RE = /^[a-z][a-z0-9-]{1,61}[a-z0-9]$/

function validateChannelName(name: string): string {
  const canonical = name.trim().toLowerCase()
  if (!CHANNEL_NAME_RE.test(canonical)) {
    throw new CordeliaError('INVALID_CHANNEL_NAME')
  }
  return canonical
}
```

Canonicalization happens in the SDK before sending to the node. The node also validates (defense in depth).

### 11.4 DMHandle and GroupHandle

`DMHandle` and `GroupHandle` are convenience wrappers that capture the `channelId` and delegate to `c.publish()` and `c.listen()`:

```typescript
// Internal construction
class DMHandleImpl implements DMHandle {
  constructor(
    private client: Cordelia,
    public channelId: string,
    public peer: string,
    public isNew: boolean
  ) {}

  async send(content: any, opts?: PublishOptions) {
    return this.client.publish(this.channelId, content, opts)
  }

  async listen(opts?: ListenOptions) {
    return this.client.listen(this.channelId, opts)
  }
}
```

No additional state. The handle is a thin wrapper over the same `publish()`/`listen()` methods.

---

## 12. BDD Acceptance Tests

Per the BDD testing ADR (decisions/2026-03-10-testing-strategy-bdd.md), SDK acceptance tests use Cucumber/Gherkin. Feature files serve as living documentation for developers.

```gherkin
Feature: Channel subscription
  Scenario: Subscribe and receive published message
    Given a running Cordelia node
    When I subscribe to channel "engineering"
    And I publish "hello world" to "engineering"
    And I listen on "engineering"
    Then I receive an item with content "hello world"
    And the item has a valid author signature

  Scenario: Private channel requires invitation
    Given a running Cordelia node
    And a private channel "board-updates" owned by another entity
    When I subscribe to "board-updates"
    Then I receive error "NOT_AUTHORIZED"

Feature: Direct messages
  Scenario: Send and receive a DM
    Given two Cordelia nodes (alice and bob)
    When alice opens a DM with bob's public key
    And alice sends "thoughts on the pivot?" via DM
    And bob opens a DM with alice's public key
    And bob listens on the DM
    Then bob receives "thoughts on the pivot?"
    And both nodes derive the same channel ID

Feature: Group conversations
  Scenario: Remove member rotates PSK
    Given a group "project-x" with alice, bob, and carol
    When alice removes carol from "project-x"
    And alice publishes "secret plan" to "project-x"
    Then bob can read "secret plan"
    And carol cannot decrypt items published after removal
```

**Location:** `cordelia-sdk/features/`
**Step definitions:** TypeScript, alongside SDK source
**Runner:** `cucumber-js`

---

## 13. References

- **specs/channels-api.md**: Node REST API endpoints (the SDK wraps these)
- **specs/ecies-envelope-encryption.md**: Cryptographic model (SDK does no crypto)
- **specs/channel-naming.md**: Channel name rules and ID derivation
- **decisions/2026-03-09-mvp-implementation-plan.md**: WP6 scope
- **decisions/2026-03-10-testing-strategy-bdd.md**: Cucumber/Gherkin for SDK tests

---

*Draft: 2026-03-10. Review with Martin before implementation.*
