-- Quick queries to verify agent_documents data

-- 1. Count records by status
SELECT 
    status,
    COUNT(*) as count
FROM public.agent_documents
GROUP BY status
ORDER BY count DESC;

-- 2. Show last 20 submitted documents
SELECT 
    id,
    user_id,
    status,
    submitted_at,
    created_at,
    reviewed_at,
    incorporation_doc IS NOT NULL as has_incorporation,
    tourism_doc IS NOT NULL as has_tourism,
    krapin_doc IS NOT NULL as has_krapin
FROM public.agent_documents
ORDER BY submitted_at DESC
LIMIT 20;

-- 3. Show pending documents awaiting review
SELECT 
    ad.id,
    ad.user_id,
    p.email,
    p.full_name,
    ad.submitted_at,
    ad.incorporation_doc IS NOT NULL as has_incorporation,
    ad.tourism_doc IS NOT NULL as has_tourism,
    ad.krapin_doc IS NOT NULL as has_krapin
FROM public.agent_documents ad
JOIN public.profiles p ON p.id = ad.user_id
WHERE ad.status = 'pending'
ORDER BY ad.submitted_at ASC;

-- 4. Show approved documents
SELECT 
    ad.id,
    ad.user_id,
    p.email,
    p.full_name,
    ad.reviewed_at,
    ad.review_notes,
    sa.email as reviewed_by_email
FROM public.agent_documents ad
JOIN public.profiles p ON p.id = ad.user_id
LEFT JOIN public.superadmin_credentials sa ON sa.id = ad.reviewed_by
WHERE ad.status = 'approved'
ORDER BY ad.reviewed_at DESC;

-- 5. Count total uploaded documents by type
SELECT 
    COUNT(CASE WHEN incorporation_doc IS NOT NULL THEN 1 END) as incorporation_count,
    COUNT(CASE WHEN tourism_doc IS NOT NULL THEN 1 END) as tourism_count,
    COUNT(CASE WHEN krapin_doc IS NOT NULL THEN 1 END) as krapin_count,
    COUNT(CASE WHEN director_id_doc IS NOT NULL THEN 1 END) as director_id_count,
    COUNT(CASE WHEN office_photo IS NOT NULL THEN 1 END) as office_photo_count,
    COUNT(*) as total_agents
FROM public.agent_documents;

-- 6. Show documents with review history
SELECT 
    ad.id,
    ad.user_id,
    p.full_name,
    ad.status,
    ad.submitted_at,
    ad.reviewed_at,
    ad.review_notes,
    COALESCE(sa.email, 'Not reviewed') as reviewed_by
FROM public.agent_documents ad
JOIN public.profiles p ON p.id = ad.user_id
LEFT JOIN public.superadmin_credentials sa ON sa.id = ad.reviewed_by
ORDER BY ad.updated_at DESC;
