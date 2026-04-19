import { createClient } from '@supabase/supabase-js';
import 'dotenv/config';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const packages = [
  {
    name: 'JULY STANDARD PACKAGE',
    type: 'umrah',
    location: 'makkah',
    makkah_hotel_name: 'VOCCO INTERNATIONA BY IHG',
    makkah_hotel_rating: '4',
    makkah_hotel_distance: '1.6KM',
    makkah_hotel_address: 'https://maps.app.goo.gl/Z8g1odhTW3FfuqHS6',
    makkah_check_in_date: '2026-07-11',
    makkah_check_out_date: '2026-07-17',
    makkah_nights: 6,
    madinah_hotel_name: 'ROSE HOLIDAY i3',
    madinah_hotel_rating: '3',
    madinah_hotel_distance: '100M',
    madinah_hotel_address: 'https://maps.app.goo.gl/RjTGRjt4rThzkqQZ9',
    madinah_check_in_date: '2026-07-07',
    madinah_check_out_date: '2026-07-11',
    madinah_nights: 4,
    price: 1400.00,
    original_price: 1450.00,
    discount: null,
    duration: 11,
    description: 'Embark on a deeply rewarding spiritual journey with our special **Shawwal Umrah Package**. This 11-day journey allows pilgrims to experience the serenity of Madinah and the sacred atmosphere of Makkah.',
    highlights: ['Professional Guidance', 'Visit Madinah Quran Factory', 'Visit Jabal Noor Revelation Exhibition'],
    inclusions: ['UmrahVisa', 'Health Insurance', 'Return Flight', 'Accommodation in Makkah and Madinah', 'Guidance Throughout the Trip', 'Free Zamzam Water', 'Free Drawstring Bag'],
    exclusions: ['Local Transport in Kenya', 'Meals'],
    available_from: '2026-03-13',
    available_to: '2026-06-25',
    max_group_size: 50,
    min_group_size: 1,
    image_urls: ['https://pub-6f49d302c2914ae4b46223343595bbac.r2.dev/packages/dd425a00-c6d6-4571-8d44-677a2c3ede4d/1773415708209-dfcac5b5cb8cf7d4b260b7e9a965885d.jpg', 'https://pub-6f49d302c2914ae4b46223343595bbac.r2.dev/packages/dd425a00-c6d6-4571-8d44-677a2c3ede4d/1773415708804-8b4207e9a3d9e6958251d8a27e028054.webp'],
    agent_number: 'UMRH2026004',
    agent_name: 'UMANAA TRAVEL AGENCY LTD',
    status: 'Active',
    created_at: '2026-03-13 15:28:29.005+00',
    updated_at: '2026-03-13 15:28:29.005+00',
    created_by: null
  },
  {
    name: 'Premium Umrah Package - 7 Days',
    type: 'umrah',
    location: 'makkah',
    makkah_hotel_name: 'Hilton Makkah',
    makkah_hotel_rating: '5',
    makkah_hotel_distance: '500m from Haram',
    makkah_hotel_address: null,
    makkah_check_in_date: null,
    makkah_check_out_date: null,
    makkah_nights: null,
    madinah_hotel_name: 'Sheraton Madinah',
    madinah_hotel_rating: '5',
    madinah_hotel_distance: '300m from Masjid Nabawi',
    madinah_hotel_address: null,
    madinah_check_in_date: null,
    madinah_check_out_date: null,
    madinah_nights: null,
    price: 2500.00,
    original_price: 3000.00,
    discount: 17,
    duration: 7,
    description: 'Experience a spiritual journey with our premium Umrah package including 5-star hotels and VIP transportation.',
    highlights: ['VIP Transportation', '5-Star Hotels', 'Guided Tours', 'Zamzam Water'],
    inclusions: ['Hotel Accommodation', 'Transportation', 'Meals', 'Visa Assistance', 'Guided Tours'],
    exclusions: ['International Flights', 'Personal Expenses', 'Travel Insurance'],
    available_from: null,
    available_to: null,
    max_group_size: 50,
    min_group_size: 1,
    image_urls: ['https://images.unsplash.com/photo-1559592413-7cec4d0cae2b?w=800', 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=800'],
    agent_number: '+254712345678',
    agent_name: 'Al-Haram Travel Agency',
    status: 'Active',
    created_at: '2026-04-17 17:17:20.687175+00',
    updated_at: '2026-04-17 17:17:20.687175+00',
    created_by: null
  },
  {
    name: 'Economy Umrah Package - 5 Days',
    type: 'umrah',
    location: 'makkah',
    makkah_hotel_name: 'Ibis Styles Makkah',
    makkah_hotel_rating: '4',
    makkah_hotel_distance: '1km from Haram',
    makkah_hotel_address: null,
    makkah_check_in_date: null,
    makkah_check_out_date: null,
    makkah_nights: null,
    madinah_hotel_name: 'Holiday Inn Madinah',
    madinah_hotel_rating: '4',
    madinah_hotel_distance: '800m from Masjid Nabawi',
    madinah_hotel_address: null,
    madinah_check_in_date: null,
    madinah_check_out_date: null,
    madinah_nights: null,
    price: 1800.00,
    original_price: 2200.00,
    discount: 18,
    duration: 5,
    description: 'Affordable Umrah package with comfortable 4-star hotels and reliable transportation.',
    highlights: ['Comfortable Hotels', 'Group Transportation', 'Spiritual Guidance'],
    inclusions: ['Hotel Accommodation', 'Transportation', 'Daily Meals', 'Visa Processing'],
    exclusions: ['International Flights', 'Personal Expenses', 'Optional Tours'],
    available_from: null,
    available_to: null,
    max_group_size: 50,
    min_group_size: 1,
    image_urls: ['https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=800', 'https://images.unsplash.com/photo-1559592413-7cec4d0cae2b?w=800'],
    agent_number: '+254798765432',
    agent_name: 'Mecca Tours Ltd',
    status: 'Active',
    created_at: '2026-04-17 17:17:20.687175+00',
    updated_at: '2026-04-17 17:17:20.687175+00',
    created_by: null
  },
  {
    name: 'Deluxe Hajj Package - 14 Days',
    type: 'hajj',
    location: 'makkah',
    makkah_hotel_name: 'Raffles Makkah Palace',
    makkah_hotel_rating: '5',
    makkah_hotel_distance: '200m from Haram',
    makkah_hotel_address: null,
    makkah_check_in_date: null,
    makkah_check_out_date: null,
    makkah_nights: null,
    madinah_hotel_name: 'The St. Regis Madinah',
    madinah_hotel_rating: '5',
    madinah_hotel_distance: '150m from Masjid Nabawi',
    madinah_hotel_address: null,
    madinah_check_in_date: null,
    madinah_check_out_date: null,
    madinah_nights: null,
    price: 4500.00,
    original_price: 5500.00,
    discount: 18,
    duration: 14,
    description: 'Complete Hajj pilgrimage with premium accommodations and comprehensive services.',
    highlights: ['Luxury Accommodation', 'Private Transportation', 'Personal Guide', 'VIP Access'],
    inclusions: ['Premium Hotels', 'Private Transport', 'All Meals', 'Complete Visa Service', 'Personal Guide'],
    exclusions: ['International Flights', 'Personal Expenses', 'Health Insurance'],
    available_from: null,
    available_to: null,
    max_group_size: 50,
    min_group_size: 1,
    image_urls: ['https://images.unsplash.com/photo-1559592413-7cec4d0cae2b?w=800', 'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=800'],
    agent_number: '+254723456789',
    agent_name: 'Sacred Journeys',
    status: 'Active',
    created_at: '2026-04-17 17:17:20.687175+00',
    updated_at: '2026-04-17 17:17:20.687175+00',
    created_by: null
  }
];

async function seedPackages() {
  try {
    console.log('🌱 Starting package seeding...');
    
    for (const pkg of packages) {
      const { data, error } = await supabase
        .from('packages')
        .insert([pkg])
        .select();
      
      if (error) {
        console.error(`❌ Error inserting ${pkg.name}:`, error);
      } else {
        console.log(`✅ Inserted: ${pkg.name}`);
      }
    }
    
    console.log('✅ Seeding complete!');
    process.exit(0);
  } catch (err) {
    console.error('❌ Seeding failed:', err);
    process.exit(1);
  }
}

seedPackages();
