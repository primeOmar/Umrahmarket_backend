-- Debug & Fix RLS Policies for agent_documents
-- Run this if documents aren't being inserted

-- 1. Check current RLS status
SELECT 
    schemaname,
    tablename,
    rowsecurity
FROM pg_tables
WHERE tablename = 'agent_documents';

-- 2. Check existing policies
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    qual,
    with_check
FROM pg_policies
WHERE tablename = 'agent_documents'
ORDER BY policyname;

-- 3. If RLS is enabled but you get insert errors, disable RLS temporarily for testing
-- ALTER TABLE public.agent_documents DISABLE ROW LEVEL SECURITY;

-- 4. Or create permissive policies that allow service role (bypasses RLS anyway)
DROP POLICY IF EXISTS "agent_documents_service_role" ON public.agent_documents;

CREATE POLICY "agent_documents_service_role"
  ON public.agent_documents
  FOR ALL
  USING (true)
  WITH CHECK (true);

-- 5. Verify policies are in place
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    qual,
    with_check
FROM pg_policies
WHERE tablename = 'agent_documents'
ORDER BY policyname;

-- 6. Test insert with service role client
-- This query will show if inserts are working
INSERT INTO public.agent_documents (user_id, status) 
VALUES (gen_random_uuid(), 'pending')
ON CONFLICT (user_id) DO UPDATE
SET updated_at = now()
RETURNING id, user_id, status, created_at;

-- 7. Check the records that were inserted
SELECT id, user_id, status, submitted_at, created_at 
FROM public.agent_documents 
ORDER BY created_at DESC 
LIMIT 10;
