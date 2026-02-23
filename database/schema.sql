-- Create health check table for Supabase connection verification
CREATE TABLE IF NOT EXISTS public._health_check (
    id SERIAL PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'ok',
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    version TEXT DEFAULT '1.0.0'
);

-- Insert a default health check record
INSERT INTO public._health_check (status, version)
VALUES ('ok', '1.0.0')
ON CONFLICT DO NOTHING;

-- Enable Row Level Security (RLS) if needed
ALTER TABLE public._health_check ENABLE ROW LEVEL SECURITY;

-- Create policy to allow read access (for health checks)
CREATE POLICY "_health_check_select" ON public._health_check
    FOR SELECT USING (true);