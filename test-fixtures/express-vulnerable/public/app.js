// SCR-012: API key exposed in frontend/public directory
const API_KEY = 'sk-frontendexposedkey1234567890abcdefghijklmnop';
const STRIPE_KEY = 'pk-liveabcdefghijklmnopqrstuvwxyz123456789012';

fetch('/api/data', {
  headers: { 'Authorization': `Bearer ${API_KEY}` }
});
