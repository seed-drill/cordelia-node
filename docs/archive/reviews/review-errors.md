# Review Pass 12: Error Catalog

**Date**: 2026-03-11
**Specs reviewed**: 5 (ecies-envelope-encryption.md, channels-api.md, channel-naming.md, sdk-api-reference.md, network-protocol.md)

---

## Summary

35 findings. The dominant issue: **401 auth errors are systematically missing from every endpoint** (15 of 15 endpoints, now 17 with list-dms and list-groups added post-review). Rate limit errors (429) defined in §9 but not reflected in endpoint error lists. P2P rejection formats are prose, not structured. Global 401 statement in §1.3 covers all endpoints including new ones.

---

## Category A: Missing 401 Authentication Errors (15 endpoints)

Every API endpoint requires bearer token auth (§1.3) but none document the 401 error case.

| ID | Endpoint | Other Missing Errors |
|----|----------|---------------------|
| EC-01 | POST /channels/subscribe | 429 (rate limit), 403 (channel cap) |
| EC-02 | POST /channels/publish | 429 (rate limit) |
| EC-03 | POST /channels/listen | -- |
| EC-04 | POST /channels/list | No error section at all |
| EC-05 | POST /channels/unsubscribe | -- |
| EC-06 | POST /channels/info | No error section at all |
| EC-07 | POST /channels/dm | 429 (rate limit) |
| EC-08 | POST /channels/group | 429 (rate limit) |
| EC-09 | POST /channels/group/invite | -- |
| EC-10 | POST /channels/group/remove | -- |
| EC-11 | POST /channels/rotate-psk | -- |
| EC-12 | POST /channels/delete-item | -- |
| EC-13 | POST /channels/search | 500 (query timeout) |
| EC-14 | POST /channels/identity | No error section at all |
| EC-15 | GET /metrics | 500 (collection failure) |

**Resolution**: Add a global auth error statement to §1.3: "All endpoints return `401 unauthorized` with body `{"error": {"code": "unauthorized", "message": "Missing or invalid bearer token"}}` when the Authorization header is missing, malformed, or contains an invalid token. This applies to all endpoints and is not repeated in individual endpoint documentation."

This is cleaner than adding 401 to every endpoint.

---

## Category B: Rate Limit Errors Not in Endpoint Docs

§9.1 defines rate limits. §9.4 defines the 429 response format. But individual endpoints don't mention 429.

| ID | Endpoint | Rate Limit (from §9.1) |
|----|----------|----------------------|
| EC-16 | /channels/subscribe | 1/sec per entity + 50 channel cap |
| EC-17 | /channels/publish | 100/min per channel |
| EC-18 | /channels/dm | 5/min per entity |
| EC-19 | /channels/group | 5/min per entity |

**Resolution**: Add to §9.1: "Rate-limited endpoints return `429 rate_limited` with the format defined in §9.4. Refer to the rate limit table below for per-endpoint limits." Then add a column to the rate limit table: "Applies to endpoint".

---

## Category C: Error Structure Inconsistency

### EC-20: Different 4xx responses have different field sets
**Severity**: MEDIUM

| Status | Fields | Defined in |
|--------|--------|-----------|
| 400-404 | code, message | §2 |
| 413 | code, message, used_bytes, quota_bytes | §9.3 |
| 429 | code, message, retry_after_seconds | §9.4 |

**Resolution**: Define in §2: "All error responses use the base format `{error: {code, message}}`. Status-specific extensions: 413 adds `used_bytes` and `quota_bytes`; 429 adds `retry_after_seconds`. Unknown fields MUST be ignored by clients."

---

## Category D: P2P Message Rejection Formats

Network protocol documents failure cases in prose but doesn't define structured rejection responses.

| ID | Mini-Protocol | Issue | Resolution |
|----|--------------|-------|-----------|
| EC-21 | Message framing (§3.1) | Oversized message: "stream is reset" -- no error code | Define QUIC app error code 0x03 (oversized_message) |
| EC-22 | Handshake (§4.1.3) | Missing: malformed TLS cert rejection | Add case: "identity extraction failed" |
| EC-23 | Keep-Alive (§4.2) | No timeout specification | Add: 60s timeout -> mark Cold, no retry |
| EC-24 | Peer-Sharing (§4.3) | Invalid address rejection format undefined | Silent drop of invalid addresses, log warning |
| EC-25 | Channel-Announce (§4.4.2) | Digest mismatch handling undefined | Mismatch -> ChannelListResponse (already implied, make explicit) |
| EC-26 | Channel Descriptor (§4.4.6) | Conflicting creator_id rejection undefined | Silent drop, log warning. NOT a ban (legitimate partition) |
| EC-27 | Item-Sync (§4.5) | "Reject the item" -- mechanism undefined | Drop item, count in verification_failed counter. >10% failure rate -> mark Cold |
| EC-28 | Item-Push (§4.6) | PushAck has single `rejected` counter -- no categorisation | Split into: dedup_dropped, policy_rejected, rate_limited, verification_failed |
| EC-29 | PSK-Exchange (§4.7) | Rejection response format undefined | Add error field to PSKResponse: `{status: "denied", reason: "not_authorized" \| "not_found"}` |

---

## Category E: SDK Error Type Gaps

### EC-30: Missing SDK error codes
**Severity**: MEDIUM
**Spec**: sdk-api-reference.md §8.1

SDK defines 11 error codes. API surface has gaps:

| Missing SDK Code | Maps to | When |
|-----------------|---------|------|
| QUOTA_EXCEEDED | 413 with quota fields | Storage quota full |
| TIMEOUT | 500 or client-side | Search query timeout, listen polling timeout |
| CHANNEL_LIMIT_REACHED | 403 with specific code | 50-channel cap hit |

### EC-31: NOT_AUTHORIZED is ambiguous
**Severity**: MEDIUM

Same error code for "not a channel member" (publish) and "channel is invite_only" (subscribe). SDK should distinguish via error context.

**Resolution**: Add `context` field to CordeliaError: `{ code: 'NOT_AUTHORIZED', context: 'invite_only' | 'not_a_member' | 'not_owner' | 'not_admin' }`

---

## Category F: Error Code Namespace

### EC-32: No versioning or stability guarantee
**Severity**: MEDIUM

Error codes (`bad_request`, `unauthorized`, etc.) are not formally registered. No guarantee of stability across versions.

**Resolution**: Add to §2: "Error codes are stable identifiers. Once published, a code is never removed or changed in meaning. New codes may be added in future versions. Clients MUST handle unknown codes as `internal_error`."

### EC-33: Inconsistent naming across layers
**Severity**: LOW

API uses snake_case (`bad_request`), P2P uses informal text ("invalid magic"), SDK uses SCREAMING_SNAKE (`NOT_AUTHORIZED`).

**Resolution**: Define canonical error code enum used across all layers: `unauthorized | not_authorized | bad_request | not_found | conflict | payload_too_large | quota_exceeded | rate_limited | timeout | internal_error`. SDK maps to SCREAMING_SNAKE. P2P maps to same codes in CBOR.

---

## Category G: Retryability Matrix

### EC-34: No retry guidance anywhere
**Severity**: MEDIUM

**Resolution**: Add to §2 or new §2.1:

| Status | Code | Retryable? | Guidance |
|--------|------|-----------|----------|
| 400 | bad_request | No | Client bug. Fix request. |
| 401 | unauthorized | No | Auth failure. Check token. |
| 403 | not_authorized | No | Permission denied. |
| 404 | not_found | No | Resource doesn't exist. |
| 409 | conflict | Yes | Exponential backoff, max 3 retries. |
| 413 | payload_too_large / quota_exceeded | No | Reduce payload or free storage. |
| 429 | rate_limited | Yes | Use retry_after_seconds if present, else exponential backoff. |
| 500 | internal_error | Yes | Exponential backoff, max 5 retries. |

### EC-35: P2P error severity tiers undefined
**Severity**: MEDIUM

**Resolution**: Add to network-protocol.md §5.6:

| Tier | Action | Examples |
|------|--------|---------|
| Transient | Mark Cold, 1 hour | Malformed message, timeout, digest mismatch |
| Moderate | Ban 24 hours | Signature verification failure, policy violation |
| Permanent | Ban forever | Identity mismatch, cryptographic proof failure |

---

## Consolidated Endpoint Error Table

Complete error surface per endpoint (specified + missing):

| Endpoint | 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 |
|----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| subscribe | Y | **M** | Y | -- | Y | -- | **M** | -- |
| publish | Y | **M** | Y | Y | -- | Y | **M** | -- |
| listen | -- | **M** | Y | Y | -- | -- | -- | -- |
| list | -- | **M** | -- | -- | -- | -- | -- | -- |
| unsubscribe | -- | **M** | -- | Y | -- | -- | -- | -- |
| info | -- | **M** | -- | -- | -- | -- | -- | -- |
| dm | Y | **M** | -- | -- | -- | -- | **M** | -- |
| group | Y | **M** | -- | -- | -- | -- | **M** | -- |
| group/invite | -- | **M** | Y | Y | -- | -- | -- | -- |
| group/remove | -- | **M** | Y | Y | -- | -- | -- | -- |
| rotate-psk | -- | **M** | Y | Y | -- | -- | -- | -- |
| delete-item | -- | **M** | Y | Y | -- | -- | -- | -- |
| search | Y | **M** | Y | Y | -- | -- | -- | **M** |
| identity | -- | **M** | -- | -- | -- | -- | -- | -- |
| metrics (GET) | -- | **M** | -- | -- | -- | -- | -- | **M** |

Y = specified, **M** = missing (must add)

---

## Recommended Fix Approach

Rather than adding 401/429 to every endpoint individually (repetitive), the cleanest fix is:

1. **§1.3 or new §2.1**: Global auth error statement ("all endpoints return 401 when token missing/invalid")
2. **§9.1**: Link rate limits to specific endpoints with 429 reference
3. **§2**: Unified error format with extension fields for 413/429
4. **§2 or new §2.2**: Retryability matrix
5. **Network protocol §5.6**: P2P error severity tiers

This keeps each endpoint's error section focused on endpoint-specific errors (400 validation, 403 permissions, 404 not found, 409 conflict) without repeating universal errors.

---

*Review Pass 12 complete. 2026-03-11.*
