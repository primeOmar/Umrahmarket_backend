/**
 * Shared package normaliser — converts raw DB shape → UI shape.
 * Import from here instead of App.jsx to avoid circular dependencies.
 */
export const normalise = (pkg) => ({
  ...pkg,
  title:         pkg.name,
  originalPrice: Number(pkg.original_price ?? 0),
  hotelRating:   pkg.makkah_hotel_rating ? `${pkg.makkah_hotel_rating}★` : '',
  distance:      pkg.makkah_hotel_distance
    ? `${Number(pkg.makkah_hotel_distance).toLocaleString()}m from Haram`
    : '',
  image: (Array.isArray(pkg.image_urls) && pkg.image_urls[0])
    || 'https://images.unsplash.com/photo-1564769662533-4f00a87b4056?auto=format&fit=crop&w=800&q=80',
  images: Array.isArray(pkg.image_urls) && pkg.image_urls.length
    ? pkg.image_urls
    : ['https://images.unsplash.com/photo-1564769662533-4f00a87b4056?auto=format&fit=crop&w=800&q=80'],
  price:      Number(pkg.price    ?? 0),
  duration:   Number(pkg.duration ?? 0),
  discount:   Number(pkg.discount ?? 0),
  rating:     Number(pkg.makkah_hotel_rating ?? 0),
  includes:   Array.isArray(pkg.inclusions) ? pkg.inclusions : [],
  excludes:   Array.isArray(pkg.exclusions) ? pkg.exclusions : [],
  highlights: Array.isArray(pkg.highlights) ? pkg.highlights : [],
});