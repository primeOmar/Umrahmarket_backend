import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import crypto from 'crypto';

const REGION = 'auto';

const s3 = new S3Client({
  region: REGION,
  endpoint: process.env.R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

export async function uploadToR2(buffer, originalName, contentType) {
  const key = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${originalName.replace(/[^a-zA-Z0-9.-]/g,'')}`;
  const params = {
    Bucket: process.env.R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ACL: 'private'
  };
  await s3.send(new PutObjectCommand(params));
  const url = `${process.env.R2_ENDPOINT}/${process.env.R2_BUCKET}/${key}`;
  return { key, url };
}
