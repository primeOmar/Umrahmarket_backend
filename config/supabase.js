import { createClient } from '@supabase/supabase-js';
import config from './security.config.js';
import logger from './logger.js';

/**
 * Supabase Client Configuration
 * Secure initialization with proper error handling
 */

// Validate Supabase configuration
if (!config.supabase.url || !config.supabase.anonKey) {
  throw new Error('Supabase URL and Anon Key are required. Check your .env file.');
}

// Client options for enhanced security
const supabaseOptions = {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    storage: undefined, // Don't use localStorage on server
    flowType: 'pkce', // Use PKCE flow for enhanced security
  },
  db: {
    schema: 'public',
  },
  global: {
    headers: {
      'x-application-name': 'secure-auth-backend',
    },
  },
};

// Create Supabase client for public operations
export const supabase = createClient(
  config.supabase.url,
  config.supabase.anonKey,
  supabaseOptions
);

// Create admin client with service role key (use carefully!)
export const supabaseAdmin = config.supabase.serviceRoleKey
  ? createClient(config.supabase.url, config.supabase.serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    })
  : null;

// Helper function to verify Supabase connection
export const verifySupabaseConnection = async () => {
  try {
    const { data, error } = await supabase
      .from('_health_check')
      .select('*')
      .limit(1);
    
    if (error && error.code !== 'PGRST116') {
      // PGRST116 is "table not found" which is fine for health check
      logger.warn('Supabase connection check failed', { error: error.message });
      return false;
    }
    
    logger.info('Supabase connection verified successfully');
    return true;
  } catch (error) {
    logger.error('Failed to verify Supabase connection', { error: error.message });
    return false;
  }
};

// Helper function to get user from token
export const getUserFromToken = async (token) => {
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error) {
      logger.warn('Failed to get user from token', { error: error.message });
      return null;
    }
    
    return user;
  } catch (error) {
    logger.error('Error getting user from token', { error: error.message });
    return null;
  }
};

// Helper function to refresh session
export const refreshUserSession = async (refreshToken) => {
  try {
    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });
    
    if (error) {
      logger.warn('Failed to refresh session', { error: error.message });
      return null;
    }
    
    return data;
  } catch (error) {
    logger.error('Error refreshing session', { error: error.message });
    return null;
  }
};

// Helper function to sign out user
export const signOutUser = async (token) => {
  try {
    const { error } = await supabase.auth.signOut(token);
    
    if (error) {
      logger.warn('Failed to sign out user', { error: error.message });
      return false;
    }
    
    return true;
  } catch (error) {
    logger.error('Error signing out user', { error: error.message });
    return false;
  }
};

export default supabase;