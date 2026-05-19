/**
 * Database Migration Runner
 * Applies pending SQL migrations from /migrations directory
 * Usage: node migrations/run.js
 */

import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE environment variable');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

async function runMigrations() {
  try {
    const migrationDir = __dirname;
    const files = fs.readdirSync(migrationDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    if (files.length === 0) {
      console.log('✓ No migrations to run');
      return;
    }

    console.log(`Running ${files.length} migration(s)...\n`);

    for (const file of files) {
      const filePath = path.join(migrationDir, file);
      const sql = fs.readFileSync(filePath, 'utf-8');

      console.log(`► Running: ${file}`);

      const { error } = await supabase.rpc('exec_sql', { sql });
      if (error && !error.message.includes('already exists')) {
        console.error(`  ✗ Failed: ${error.message}`);
        continue;
      }

      console.log(`  ✓ Completed`);
    }

    console.log('\n✓ Migration complete');
  } catch (error) {
    console.error('Migration error:', error);
    process.exit(1);
  }
}

runMigrations();
