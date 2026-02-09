Here is the design and implementation plan to add Marketplace Storage and Autos-loading for Trust Pulse.

### 1. Data Model

We will add a dedicated table `submission_trust_pulse`. This allows fetching the main `submissions` table list without carrying the weight of the optional Trust Pulse JSON blobs (bloat reduction) and separates the storage lifecycle.

**New Table: `submission_trust_pulse`**

| Column | Type | Description |
| :--- | :--- | :--- |
| `submission_id` | `TEXT` | Primary Key, Foreign Key to `submissions(submission_id)`. |
| `trust_pulse_json` | `TEXT` | The full JSON document. Max 24KB limit enforced by API. |
| `hash_b64u` | `TEXT` | SHA-256 hash of the JSON (for integrity checks). |
| `status` | `TEXT` | Verification status: `'verified'` (matches URM hash), `'unverified'` (no hash in URM), or `'mismatch'` (hash differs). |
| `created_at` | `TEXT` | ISO timestamp. |

**SQL Migration:**
```sql
CREATE TABLE IF NOT EXISTS submission_trust_pulse (
  submission_id TEXT PRIMARY KEY,
  trust_pulse_json TEXT NOT NULL,
  hash_b64u TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (submission_id) REFERENCES submissions(submission_id)
);
```

### 2. API Contract

**Ingestion: `POST /v1/bounties/{id}/submit`**

*   **Request Schema Change:** Add optional `trust_pulse` field (JSON Object).
    ```json
    {
      "worker_did": "...",
      "proof_bundle_envelope": {...},
      "urm": {...},
      "trust_pulse": { "trust_pulse_version": "1", ... } // NEW
    }
    ```
*   **Behavior:** If provided, the server calculates the hash, compares it against `urm.metadata.trust_pulse.artifact_hash_b64u` (if present), and stores it.

**Retrieval: `GET /v1/submissions/{submission_id}/trust-pulse`**

*   **Headers:** Requires `Authorization: Bearer <BOUNTIES_ADMIN_KEY>` (MVP).
*   **Response (200 OK):**
    ```json
    {
      "submission_id": "...",
      "status": "verified", // verified | unverified | mismatch
      "trust_pulse": { ... } // The JSON document
    }
    ```
*   **Response (404):** If submission exists but no trust pulse is stored.

### 3. Binding & Validation

The server performs integrity checks during `POST /submit`:

1.  **URM Binding:**
    *   If `urm.metadata.trust_pulse.artifact_hash_b64u` exists:
        *   Compute SHA-256 (base64url) of the `req.body.trust_pulse` JSON.
        *   **Fail-closed:** If hashes mismatch, reject submission (400 Bad Request: Integrity Check Failed).
        *   If match, store with status `'verified'`.
    *   If `urm` or metadata pointer is missing:
        *   Store with status `'unverified'`.
2.  **Run ID Binding:**
    *   If stored, check `trust_pulse.run_id === submission.run_id` (derived from proof bundle).
    *   **Fail-close:** Reject on mismatch to prevent confusing cross-run evidence attached to a submission.
3.  **Size Limit:** Reject if JSON string length > 24KB (Trust Pulse is meant to be a summary).

### 4. Viewer UX

The layout at `/trust-pulse` is currently a static HTML page served by the GET endpoint.

*   **URL Pattern:** Users access `https://clawbounties.com/trust-pulse?submission_id=sub_123`.
*   **Safety:** Admin Keys are **never** passed in the URL.
*   **Flow:**
    1.  Page loads. Checks for `?submission_id=`.
    2.  If present, JS checks `localStorage` for an Admin Key or prompts the user via a simple `prompt()` or input field overlay.
    3.  JS performs `fetch('/v1/submissions/sub_123/trust-pulse', { headers: { Authorization... } })`.
    4.  If 401: Ask for key again.
    5.  On success: Populate the JSON viewer area and show a "Verified / Unverified" badge based on the response status.

---

### 5. Implementation Plan

#### Step 1: Database Migration
Create the storage table.

**File:** `services/clawbounties/migrations/0009_trust_pulse_storage.sql`
```sql
-- Store Trust Pulse artifacts separately to keep submissions table lean
CREATE TABLE IF NOT EXISTS submission_trust_pulse (
  submission_id TEXT PRIMARY KEY,
  trust_pulse_json TEXT NOT NULL,
  hash_b64u TEXT NOT NULL,
  status TEXT NOT NULL, -- 'verified' | 'unverified' | 'mismatch'
  created_at TEXT NOT NULL
);
```

#### Step 2: Backend Logic (Service)
Update `services/clawbounties/src/index.ts`.

**A. Helper function to validate URM binding:**
```typescript
function validateTrustPulseBinding(
  pulseJson: unknown, 
  pulseHash: string, 
  urm?: Record<string, unknown> | null
): { status: 'verified' | 'unverified'; error?: string } {
  if (!isRecord(urm) || !urm.metadata || !isRecord(urm.metadata)) {
    return { status: 'unverified' };
  }
  
  const tpMeta = urm.metadata.trust_pulse;
  if (!isRecord(tpMeta)) {
    return { status: 'unverified' };
  }

  const expectedHash = tpMeta.artifact_hash_b64u;
  if (typeof expectedHash === 'string' && isNonEmptyString(expectedHash)) {
     if (expectedHash.trim() !== pulseHash) {
       return { status: 'unverified', error: 'Integrity mismatch: Trust Pulse does not match URM metadata hash' };
     }
     return { status: 'verified' };
  }
  
  return { status: 'unverified' };
}
```

**B. Update `handleSubmitBounty`:**
1.  Parse `request.trust_pulse`.
2.  Canonicalize/Stringify (JCS preferred, stable stringify fallback) -> Check size (< 24KB).
3.  Compute Hash.
4.  Run validation logic (Run ID check + Hash check).
5.  If valid, prepare separate D1 Insert.
6.  Execute insert alongside submission insert (ideally in batch, or immediately after).

**C. Add `handleGetTrustPulse`:**
1.  Verify Admin Auth.
2.  `SELECT * FROM submission_trust_pulse WHERE submission_id = ?`.
3.  Return JSON.

#### Step 3: Viewer UI Update
Update the HTML string in `trustPulseViewerPage` function in `src/index.ts`.

*   Add logic to parse `window.location.search`.
*   Add a "Fetch from Submission" UI container appearing only when ID valid.
*   Add strict "Input Admin Key" logic (in-memory only, or sessionStorage).

#### Reference Implementation Details (Changes to `services/clawbounties/src/index.ts`)

**1. Add DB Access method:**

```typescript
async function getTrustPulse(db: D1Database, submissionId: string): Promise<{ trust_pulse_json: string; status: string } | null> {
  const row = await db.prepare('SELECT trust_pulse_json, status FROM submission_trust_pulse WHERE submission_id = ?')
    .bind(submissionId)
    .first();
  if (!row) return null;
  return { 
    trust_pulse_json: row.trust_pulse_json as string, 
    status: row.status as string 
  };
}

// In handleSubmitBounty, inside the insert block:
// ...
if (request.trust_pulse) {
   // Assuming stableStringify and sha256B64uUtf8 functions exist (they do in File 1)
   const pulseStr = stableStringify(request.trust_pulse);
   if (pulseStr.length > 24 * 1024) throw new Error('TRUST_PULSE_TOO_LARGE'); 
   const pulseHash = await sha256B64uUtf8(pulseStr);
   
   // Validation checks... (RunID match, URM Hash match)
   // ...

   await db.prepare('INSERT INTO submission_trust_pulse ...').bind(...).run();
}
```

**2. Update Viewer Page HTML Script:**

```javascript
/* Inside existing script tag in trustPulseViewerPage */

const params = new URLSearchParams(window.location.search);
const submissionId = params.get('submission_id');

if (submissionId) {
  // Add UI for "Locked content"
  const container = document.createElement('div');
  container.className = 'fetch-container'; // inline styles would applied
  container.innerHTML = `
    <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin-bottom: 20px;">
      <h3 style="margin-top:0;">Load Trust Pulse for ${esc(submissionId)}</h3>
      <div style="display:flex; gap:8px;">
        <input type="password" id="apiKey" placeholder="Admin Key" style="flex:1; padding: 6px;">
        <button id="btnFetch">Fetch</button>
      </div>
    </div>
  `;
  document.querySelector('main').insertBefore(container, document.getElementById('input').parentNode); // Insert before textarea
  
  document.getElementById('btnFetch').addEventListener('click', async () => {
    const key = document.getElementById('apiKey').value;
    if(!key) return alert('Key required via MVP rules');
    
    try {
      const res = await fetch(`/v1/submissions/${submissionId}/trust-pulse`, {
        headers: { 'Authorization': 'Bearer ' + key }
      });
      if(!res.ok) throw new Error(res.statusText);
      const data = await res.json();
      
      elInput.value = JSON.stringify(data.trust_pulse, null, 2);
      doRender(); // Existing render function
      
      // Update UI to show status
      if(data.status) {
         // Show badge...
      }
    } catch(e) {
      alert('Failed: ' + e.message);
    }
  });
} 
```
