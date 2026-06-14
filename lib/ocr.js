import vision from '@google-cloud/vision';
import fs from 'fs';

const client = new vision.ImageAnnotatorClient();

function normalizeText(t) {
  return (t || '').replace(/\s+/g, ' ').trim();
}

export async function extractPassportText(buffer) {
  const [result] = await client.textDetection(buffer);
  const detections = result.textAnnotations || [];
  const full = detections.length ? detections[0].description : '';
  return normalizeText(full);
}

export function findPassportNumberInText(text, passportNumber) {
  if (!text || !passportNumber) return false;
  const norm = passportNumber.replace(/\s|[^A-Z0-9]/gi, '').toUpperCase();
  const tnorm = text.replace(/\s|[^A-Z0-9]/gi, '').toUpperCase();
  return tnorm.includes(norm);
}

export function extractDatesFromText(text) {
  const results = [];
  if (!text) return results;
  // patterns: YYYY-MM-DD, DD/MM/YYYY, DD.MM.YYYY, YYMMDD
  const dateRegexes = [
    /([0-9]{4})[-\/\.](0[1-9]|1[0-2])[-\/\.](0[1-9]|[12][0-9]|3[01])/g,
    /(0[1-9]|[12][0-9]|3[01])[-\/\.](0[1-9]|1[0-2])[-\/\.](?:[0-9]{4})/g,
    /([0-9]{2})([0-1][0-9])([0-3][0-9])/g // YYMMDD (MRZ-like)
  ];
  for (const r of dateRegexes) {
    let m;
    while ((m = r.exec(text))) {
      results.push(m[0]);
    }
  }
  return results;
}

export function parseDateString(s) {
  if (!s) return null;
  // try ISO
  const iso = new Date(s);
  if (!Number.isNaN(iso.getTime())) return iso;
  // try YYMMDD
  const yyymmdd = s.match(/^([0-9]{2})([0-1][0-9])([0-3][0-9])$/);
  if (yyymmdd) {
    const y = parseInt(yyymmdd[1], 10);
    const year = y >= 70 ? 1900 + y : 2000 + y; // heuristic
    const month = parseInt(yyymmdd[2], 10) - 1;
    const day = parseInt(yyymmdd[3], 10);
    return new Date(Date.UTC(year, month, day));
  }
  // fallback null
  return null;
}
