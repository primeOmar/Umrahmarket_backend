-- Migration: Create agent_documents table
-- Purpose: Store document verification records for agent onboarding
-- Run this in Supabase SQL editor to initialize the table

CREATE TABLE IF NOT EXISTS public.agent_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE,
    incorporation_doc TEXT,
    tourism_doc TEXT,
    krapin_doc TEXT,
    director_id_doc TEXT,
    office_photo TEXT[],
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    review_notes TEXT,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    submitted_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES public.superadmin_credentials(id) ON DELETE SET NULL
);

-- Enable Row Level Security
ALTER TABLE public.agent_documents ENABLE ROW LEVEL SECURITY;

-- Agents can view/insert/update their own documents
CREATE POLICY "agent_documents_agents_select" ON public.agent_documents
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "agent_documents_agents_insert" ON public.agent_documents
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "agent_documents_agents_update" ON public.agent_documents
    FOR UPDATE USING (auth.uid() = user_id);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_agent_documents_user_id ON public.agent_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_documents_status ON public.agent_documents(status);
CREATE INDEX IF NOT EXISTS idx_agent_documents_submitted_at ON public.agent_documents(submitted_at DESC);

-- Verify table creation
SELECT 
    table_name, 
    column_name, 
    data_type, 
    is_nullable
FROM information_schema.columns 
WHERE table_schema = 'public' AND table_name = 'agent_documents'
ORDER BY ordinal_position;
