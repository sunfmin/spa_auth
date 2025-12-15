'use strict';

const { verifyToken, extractBearerToken } = require('./jwt');

/**
 * Lambda@Edge function for validating JWT tokens at CloudFront
 * 
 * This function runs on viewer-request events and validates the JWT token
 * from the Authorization header. If valid, it adds user info headers.
 * If invalid, it returns a 401 response.
 * 
 * Environment variables (set via CloudFront function associations):
 * - JWT_SECRET: The secret key for JWT verification
 * 
 * Protected paths can be configured in the PROTECTED_PATHS array.
 */

// Paths that require authentication (configure as needed)
const PROTECTED_PATHS = [
  '/api/v1/users',
  '/api/v1/roles',
  '/api/v1/spa-sections',
  '/api/v1/permissions',
];

// Paths that are always public
const PUBLIC_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
  '/api/v1/auth/validate',
  '/api/v1/oauth/google/start',
  '/api/v1/oauth/google/callback',
  '/api/v1/password/reset/request',
  '/api/v1/password/reset',
  '/health',
];

/**
 * Check if a path requires authentication
 * @param {string} uri - Request URI
 * @returns {boolean}
 */
function requiresAuth(uri) {
  // Check if path is explicitly public
  for (const publicPath of PUBLIC_PATHS) {
    if (uri === publicPath || uri.startsWith(publicPath + '/')) {
      return false;
    }
  }

  // Check if path is protected
  for (const protectedPath of PROTECTED_PATHS) {
    if (uri === protectedPath || uri.startsWith(protectedPath + '/')) {
      return true;
    }
  }

  // Default: require auth for /api/ paths
  return uri.startsWith('/api/');
}

/**
 * Generate 401 Unauthorized response
 * @param {string} message - Error message
 * @returns {object} - CloudFront response object
 */
function unauthorizedResponse(message) {
  return {
    status: '401',
    statusDescription: 'Unauthorized',
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'application/json' }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    },
    body: JSON.stringify({
      code: 'UNAUTHORIZED',
      message: message || 'Authentication required',
    }),
  };
}

/**
 * Lambda@Edge handler for viewer-request events
 * @param {object} event - CloudFront event
 * @param {object} context - Lambda context
 * @param {function} callback - Callback function
 */
exports.handler = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const uri = request.uri;

  // Skip auth for public paths
  if (!requiresAuth(uri)) {
    callback(null, request);
    return;
  }

  // Get JWT secret from environment or custom origin header
  const jwtSecret = process.env.JWT_SECRET || 
    (request.origin && request.origin.custom && request.origin.custom.customHeaders && 
     request.origin.custom.customHeaders['x-jwt-secret'] && 
     request.origin.custom.customHeaders['x-jwt-secret'][0].value);

  if (!jwtSecret) {
    console.error('JWT_SECRET not configured');
    callback(null, unauthorizedResponse('Server configuration error'));
    return;
  }

  // Extract token from Authorization header
  const authHeader = request.headers['authorization'] && 
    request.headers['authorization'][0] && 
    request.headers['authorization'][0].value;

  const token = extractBearerToken(authHeader);
  if (!token) {
    callback(null, unauthorizedResponse('Missing or invalid Authorization header'));
    return;
  }

  // Verify token
  const payload = verifyToken(token, jwtSecret);
  if (!payload) {
    callback(null, unauthorizedResponse('Invalid or expired token'));
    return;
  }

  // Add user info headers for downstream services
  request.headers['x-user-id'] = [{ key: 'X-User-ID', value: payload.user_id || payload.sub }];
  request.headers['x-user-email'] = [{ key: 'X-User-Email', value: payload.email || '' }];
  request.headers['x-user-roles'] = [{ key: 'X-User-Roles', value: (payload.roles || []).join(',') }];
  request.headers['x-user-sections'] = [{ key: 'X-User-Sections', value: (payload.sections || []).join(',') }];

  // Continue to origin
  callback(null, request);
};

/**
 * Async handler for newer Lambda runtime
 * @param {object} event - CloudFront event
 * @returns {object} - Request or response
 */
exports.handlerAsync = async (event) => {
  return new Promise((resolve) => {
    exports.handler(event, {}, (err, result) => {
      resolve(result);
    });
  });
};
