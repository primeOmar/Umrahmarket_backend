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

-- Create packages table
CREATE TABLE IF NOT EXISTS public.packages (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT CHECK (type IN ('umrah', 'hajj')),
    location TEXT CHECK (location IN ('makkah', 'madinah', 'jeddah')),
    description TEXT,
    price DECIMAL(10,2),
    original_price DECIMAL(10,2),
    discount DECIMAL(5,2) DEFAULT 0,
    duration INTEGER,
    available_from DATE,
    available_to DATE,
    min_group_size INTEGER DEFAULT 1,
    max_group_size INTEGER DEFAULT 50,
    makkah_hotel_name TEXT,
    makkah_hotel_rating DECIMAL(2,1),
    makkah_hotel_distance TEXT,
    makkah_hotel_address TEXT,
    makkah_check_in_date DATE,
    makkah_check_out_date DATE,
    madinah_hotel_name TEXT,
    madinah_hotel_rating DECIMAL(2,1),
    madinah_hotel_distance TEXT,
    madinah_hotel_address TEXT,
    madinah_check_in_date DATE,
    madinah_check_out_date DATE,
    highlights TEXT[],
    inclusions TEXT[],
    exclusions TEXT[],
    image_urls TEXT[],
    created_by UUID,
    agent_name TEXT,
    agent_number TEXT,
    status TEXT DEFAULT 'Active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE public.packages ENABLE ROW LEVEL SECURITY;

-- Create policies for packages
CREATE POLICY "packages_select" ON public.packages
    FOR SELECT USING (true);

CREATE POLICY "packages_insert" ON public.packages
    FOR INSERT WITH CHECK (true);

CREATE POLICY "packages_update" ON public.packages
    FOR UPDATE USING (true);

CREATE POLICY "packages_delete" ON public.packages
    FOR DELETE USING (true);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_packages_status ON public.packages(status);
CREATE INDEX IF NOT EXISTS idx_packages_type ON public.packages(type);
CREATE INDEX IF NOT EXISTS idx_packages_created_at ON public.packages(created_at DESC);