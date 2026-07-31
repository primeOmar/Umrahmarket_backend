import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Read and parse CSV
function parseCSV(csvText) {
  const lines = csvText.trim().split('\n');
  const headers = lines[0].split(',').map(h => h.replace(/"/g, '').trim());

  return lines.slice(1).map(line => {
    const values = line.split(',').map(v => v.replace(/"/g, '').trim());
    const obj = {};

    headers.forEach((header, index) => {
      let value = values[index] || '';

      // Parse JSON arrays
      if (header === 'highlights' || header === 'inclusions' || header === 'exclusions' || header === 'image_urls') {
        try {
          value = JSON.parse(value);
        } catch {
          value = [];
        }
      }

      // Parse numbers
      if (header === 'price' || header === 'original_price' || header === 'discount' ||
          header === 'duration' || header === 'max_group_size' || header === 'min_group_size' ||
          header === 'makkah_hotel_rating' || header === 'madinah_hotel_rating') {
        const num = parseFloat(value);
        value = isNaN(num) ? null : num;
      }

      // Parse dates
      if (header.includes('date') || header === 'available_from' || header === 'available_to') {
        value = value && value !== 'null' ? value : null;
      }

      obj[header] = value;
    });

    return obj;
  });
}

async function populatePackages() {
  try {
    // Read CSV file
    const csvPath = path.join(__dirname, '../umrahmarket-main/packages_rows.csv');
    const csvText = fs.readFileSync(csvPath, 'utf8');

    // Parse CSV
    const packages = parseCSV(csvText);

    // Insert packages
    for (const pkg of packages) {
      // Prepare package data for insertion
      const packageData = {
        name: pkg.name,
        type: pkg.type,
        location: pkg.location,
        description: pkg.description,
        price: pkg.price,
        original_price: pkg.original_price,
        discount: pkg.discount,
        duration: pkg.duration,
        available_from: pkg.available_from,
        available_to: pkg.available_to,
        min_group_size: pkg.min_group_size || 1,
        max_group_size: pkg.max_group_size || 50,
        makkah_hotel_name: pkg.makkah_hotel_name || null,
        makkah_hotel_rating: pkg.makkah_hotel_rating || null,
        makkah_hotel_distance: pkg.makkah_hotel_distance || null,
        makkah_hotel_address: pkg.makkah_hotel_address || null,
        makkah_check_in_date: pkg.makkah_check_in_date || null,
        makkah_check_out_date: pkg.makkah_check_out_date || null,
        madinah_hotel_name: pkg.madinah_hotel_name || null,
        madinah_hotel_rating: pkg.madinah_hotel_rating || null,
        madinah_hotel_distance: pkg.madinah_hotel_distance || null,
        madinah_hotel_address: pkg.madinah_hotel_address || null,
        madinah_check_in_date: pkg.madinah_check_in_date || null,
        madinah_check_out_date: pkg.madinah_check_out_date || null,
        highlights: Array.isArray(pkg.highlights) ? pkg.highlights : [],
        inclusions: Array.isArray(pkg.inclusions) ? pkg.inclusions : [],
        exclusions: Array.isArray(pkg.exclusions) ? pkg.exclusions : [],
        image_urls: Array.isArray(pkg.image_urls) ? pkg.image_urls : [],
        created_by: pkg.created_by || 'ceb59d24-5957-47f4-86cf-4cf50918f3be', // Use a valid UUID
        agent_name: pkg.agent_name || 'Sample Agent',
        agent_number: pkg.agent_number || 'SAMPLE001',
        status: 'Active'
      };

      const { error } = await supabase
        .from('packages')
        .insert([packageData])
        .select();

      if (error) {
        continue;
      }
    }

  } catch (error) {
    process.exit(1);
  }
}

// Run the script
populatePackages();