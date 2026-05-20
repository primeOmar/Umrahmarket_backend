-- Updated agent_documents table schema
-- This is the current schema with all columns including the recent additions

CREATE TABLE public.agent_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  incorporation_doc text,
  tourism_doc text,
  krapin_doc text,
  director_id_doc text,
  office_photo text[],
  status text DEFAULT 'pending'::text CHECK (status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text])),
  review_notes text,
  submitted_at timestamp with time zone DEFAULT now(),
  reviewed_at timestamp with time zone,
  reviewed_by uuid,
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT agent_documents_pkey PRIMARY KEY (id),
  CONSTRAINT agent_documents_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.profiles(id),
  CONSTRAINT agent_documents_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.profiles(id)
);

-- Indexes for performance
CREATE INDEX idx_agent_documents_user_id ON public.agent_documents(user_id);
CREATE INDEX idx_agent_documents_status ON public.agent_documents(status);

-- RLS Policies (if RLS is enabled)
-- Allow agents to view their own documents
ALTER TABLE agent_documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_documents_agent_select ON agent_documents
  FOR SELECT
  USING (user_id = auth.uid());

CREATE POLICY agent_documents_agent_insert ON agent_documents
  FOR INSERT
  WITH CHECK (user_id = auth.uid());

CREATE POLICY agent_documents_agent_update ON agent_documents
  FOR UPDATE
  USING (user_id = auth.uid());

-- Allow superadmin full access (through service role)
-- No policy needed for service role (bypasses RLS)
