# Database Setup Instructions

## Issue
Documents are not being persisted to the database because the `agent_documents` table doesn't exist yet.

## Solution

### Option 1: Run in Supabase SQL Editor (Recommended)

1. Go to your Supabase Project Dashboard
2. Click **SQL Editor** (left sidebar)
3. Click **New Query**
4. Copy the entire contents of `migrations/001_create_agent_documents.sql`
5. Paste it into the SQL editor
6. Click **Run** (or Ctrl+Enter)
7. Verify: You should see column definitions appear at the bottom

### Option 2: Use Supabase CLI

```bash
# Install Supabase CLI if not already installed
npm install -g supabase

# Link your project (one-time setup)
supabase link --project-ref your-project-ref

# Run migrations
supabase migration up
```

### Option 3: Use psql directly (if you have database access)

```bash
psql "postgresql://user:password@host/database" < migrations/001_create_agent_documents.sql
```

## Debugging: Documents Not Being Inserted

If documents upload to R2 but don't appear in `agent_documents` table:

### Step 1: Check API Logs
```bash
# Backend logs should show detailed insert attempts
tail -f logs/app.log | grep "POST /api/documents"
```

### Step 2: Test the Debug Endpoint
```bash
curl http://localhost:5000/api/documents/debug/status
```

Expected response:
```json
{
  "success": true,
  "status": "ok",
  "table": "agent_documents exists",
  "recordCount": 0,
  "testInsert": {
    "success": true,
    "error": null
  }
}
```

If `testInsert.success` is `false`, there's an RLS or permission issue.

### Step 3: Fix RLS Policies

Run this SQL in Supabase SQL Editor:

```sql
-- Create permissive policy for service role
DROP POLICY IF EXISTS "agent_documents_service_role" ON public.agent_documents;

CREATE POLICY "agent_documents_service_role"
  ON public.agent_documents
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- Verify the policy exists
SELECT 
    tablename,
    policyname,
    permissive
FROM pg_policies
WHERE tablename = 'agent_documents';
```

Or run the full debug script:
```
Copy entire contents of migrations/002_fix_agent_documents_rls.sql
Paste into Supabase SQL Editor
Click Run
```

### Step 4: Verify Insert Works

In Supabase SQL Editor, run:
```sql
SELECT id, user_id, status, submitted_at, created_at 
FROM public.agent_documents 
ORDER BY created_at DESC 
LIMIT 10;
```

You should see records appearing.

## What Gets Created

The migration creates:

- **Table**: `public.agent_documents`
  - `id` (UUID, primary key)
  - `user_id` (UUID, foreign key to profiles)
  - `incorporation_doc`, `tourism_doc`, `krapin_doc`, `director_id_doc` (TEXT URLs)
  - `office_photo` (TEXT[], array of URLs)
  - `status` (TEXT: 'pending' | 'approved' | 'rejected')
  - `review_notes` (TEXT)
  - `reviewed_by`, `reviewed_at` (tracking who verified)
  - `submitted_at`, `created_at`, `updated_at` (timestamps)

- **Row Level Security** policies (agents can only see their own documents)
- **Indexes** for performance
- **Trigger** to auto-update `updated_at` on row changes

## Verification

After running the migration, run this query in SQL editor to verify:

```sql
SELECT 
    table_name, 
    column_name, 
    data_type, 
    is_nullable
FROM information_schema.columns 
WHERE table_schema = 'public' AND table_name = 'agent_documents'
ORDER BY ordinal_position;
```

You should see 14 columns listed. If the table doesn't appear, check for errors in the SQL output.

## After Migration

Once the table exists and RLS is configured, documents will be:
1. Uploaded to Cloudflare R2
2. Persisted to `agent_documents` with status='pending'
3. Visible in superadmin dashboard
4. Ready for verification workflow

## Common Issues

| Issue | Solution |
|-------|----------|
| "relation does not exist" | Run migration 001 first |
| Insert returns 403 Forbidden | Run migration 002 to fix RLS policies |
| Test insert succeeds but real inserts fail | Check that `user_id` values are valid UUIDs |
| Documents in R2 but not in DB | Check backend logs for insert errors |
| "violates unique constraint" | User already has a document record; should update not insert |
