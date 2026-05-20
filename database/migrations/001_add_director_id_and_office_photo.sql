-- Migration: Add director_id_doc and office_photo columns to agent_documents
-- Date: 2026-05-20
-- Purpose: Store R2 references for director ID and office photos

ALTER TABLE public.agent_documents
ADD COLUMN IF NOT EXISTS director_id_doc text,
ADD COLUMN IF NOT EXISTS office_photo text[];

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_agent_documents_user_id ON public.agent_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_documents_status ON public.agent_documents(status);

-- Add comment for documentation
COMMENT ON COLUMN public.agent_documents.director_id_doc IS 'R2 URL or path to director ID document';
COMMENT ON COLUMN public.agent_documents.office_photo IS 'Array of R2 URLs or paths to office photos';
