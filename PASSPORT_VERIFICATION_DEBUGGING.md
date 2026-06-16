# Passport Verification Debugging Guide

## Issue: 500 Error on POST `/api/passport/verify-image`

This guide helps diagnose and fix passport verification failures.

## Root Causes Addressed

### 1. **OCR Cache Path Not Set** ✅ FIXED
- **Problem**: Tesseract.js couldn't initialize the worker due to missing cache directory configuration
- **Solution**: Added `OCR_CACHE_PATH` environment variable:
  - Local: `OCR_CACHE_PATH=./ocr-cache`
  - Render: `OCR_CACHE_PATH=/tmp/ocr-cache`

### 2. **Image Preprocessing Errors** ✅ FIXED
- **Problem**: Sharp library failures on certain image formats weren't properly logged
- **Solution**: Added comprehensive error handling in `preprocess()` function with detailed logging

### 3. **Worker Initialization Issues** ✅ FIXED
- **Problem**: Tesseract worker initialization failures weren't providing enough context
- **Solution**: Enhanced `getWorker()` with detailed error logging and retry logic

## Testing Locally

### Step 1: Set Up OCR Cache Directory
```bash
cd C:\Users\HomePC\Desktop\2026\web\secure-auth-backend
mkdir ocr-cache
```

### Step 2: Verify Environment Variables
Check that `.env` includes:
```env
OCR_CACHE_PATH=./ocr-cache
SUPABASE_URL=https://tngtbcpoiidnhgbjqotq.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
CLOUDFLARE_R2_ACCESS_KEY_ID=...
CLOUDFLARE_R2_SECRET_ACCESS_KEY=...
CLOUDFLARE_R2_BUCKET_NAME=packagesimages
CLOUDFLARE_ACCOUNT_ID=...
```

### Step 3: Start Backend in Development
```bash
npm run dev
```

### Step 4: Test Passport Verification Endpoint
```bash
curl -X POST http://localhost:5000/api/passport/verify-image \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: multipart/form-data" \
  -F "passport=@/path/to/passport/image.jpg" \
  -F "packageId=<PACKAGE_ID>" \
  -F "passportNumber=A1234567" \
  -F "passportExpiry=2028-12-31" \
  -F "surname=SMITH" \
  -F "givenNames=JOHN"
```

### Step 5: Check Logs
```bash
tail -f logs/application-2026-06-16.log
tail -f logs/error-2026-06-16.log
```

Look for:
- `Tesseract worker initialized successfully` - OCR initialization working
- `Starting OCR extraction` - OCR process beginning
- `OCR extraction complete` - OCR finished with result
- `Passport image uploaded to R2` - Image storage working
- Any error messages with detailed context

## Deploying to Render

### Step 1: Add Environment Variables to Render
In your Render dashboard:

```
OCR_CACHE_PATH=/tmp/ocr-cache
SUPABASE_URL=https://tngtbcpoiidnhgbjqotq.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
NODE_ENV=production
```

### Step 2: Ensure Dependencies Are Installed
Verify `package.json` includes:
```json
{
  "dependencies": {
    "tesseract.js": "^7.0.0",
    "sharp": "^0.35.1",
    "@aws-sdk/client-s3": "^3.1006.0",
    "file-type": "^18.7.0"
  }
}
```

### Step 3: Deploy
```bash
git add -A
git commit -m "Fix: Improve passport verification error handling and logging"
git push origin main
```

Render will automatically deploy when you push to main.

### Step 4: Monitor Render Logs
```bash
# View real-time logs from Render CLI
render logs -s <SERVICE_ID>
```

Or check the Render dashboard > Logs tab.

## Common Issues & Solutions

### Issue: "OCR worker initialization failed"
**Cause**: Tesseract language data can't be downloaded or cached
**Solutions**:
1. Verify `OCR_CACHE_PATH` is set and writable
2. Check disk space (Render has limited storage)
3. Ensure network isn't blocked on Render

### Issue: "Image preprocessing failed"
**Cause**: Sharp can't process the image format
**Solutions**:
1. Ensure image is valid JPEG, PNG, or WebP
2. Check image isn't corrupted
3. Try different image format

### Issue: "Passport image upload to R2 failed"
**Cause**: CloudFlare credentials invalid
**Solutions**:
1. Verify all `CLOUDFLARE_R2_*` env vars are correct
2. Check credentials haven't been rotated
3. Verify bucket exists and has write permissions

### Issue: "passport_verifications upsert failed"
**Cause**: Supabase database error
**Solutions**:
1. Verify `SUPABASE_SERVICE_ROLE_KEY` is correct
2. Check Row Level Security (RLS) policies allow inserts
3. Verify `passport_verifications` table exists

## Performance Optimization

### OCR Processing Time
- **Band extraction**: ~2-3 seconds (MRZ area only)
- **Full image OCR**: ~5-8 seconds (fallback)
- **Total**: 7-11 seconds per image

To improve:
1. Optimize image size before upload (frontend)
2. Consider async processing for high volume
3. Cache worker to avoid reinitilization

### Reduce Timeout Issues
- Increase API timeout on frontend (currently set to default)
- Consider adding request progress tracking
- Use compression for large images

## Monitoring

### Key Metrics to Track
1. **OCR Success Rate**: % of images with detected MRZ
2. **Match Rate**: % of OCRd details matching user input
3. **Processing Time**: Time from request to response
4. **Error Rate**: % of requests returning 500

### Log Analysis
```bash
# Find all passport verification errors
grep "verifyPassportImage failed" logs/*.log

# Find OCR initialization issues
grep "Tesseract worker" logs/*.log

# Find R2 upload failures
grep "Passport image upload" logs/*.log
```

## References

- [Tesseract.js Documentation](https://github.com/naptha/tesseract.js)
- [Sharp Image Processing](https://sharp.pixelplumbing.com/)
- [CloudFlare R2 API](https://developers.cloudflare.com/r2/api/s3/)
- [Supabase JavaScript Client](https://supabase.com/docs/reference/javascript/introduction)
