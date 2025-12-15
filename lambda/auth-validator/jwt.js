'use strict';

const crypto = require('crypto');

/**
 * Verify a JWT token using HS256 algorithm
 * @param {string} token - The JWT token to verify
 * @param {string} secret - The secret key for verification
 * @returns {object|null} - Decoded payload if valid, null if invalid
 */
function verifyToken(token, secret) {
  if (!token || !secret) {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  try {
    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    if (signatureB64 !== expectedSignature) {
      return null;
    }

    // Decode header
    const header = JSON.parse(base64UrlDecode(headerB64));
    if (header.alg !== 'HS256') {
      return null;
    }

    // Decode payload
    const payload = JSON.parse(base64UrlDecode(payloadB64));

    // Check expiration
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return null;
    }

    return payload;
  } catch (e) {
    return null;
  }
}

/**
 * Decode base64url string
 * @param {string} str - Base64url encoded string
 * @returns {string} - Decoded string
 */
function base64UrlDecode(str) {
  // Add padding if needed
  const padding = 4 - (str.length % 4);
  if (padding !== 4) {
    str += '='.repeat(padding);
  }
  
  // Convert base64url to base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  
  return Buffer.from(str, 'base64').toString('utf8');
}

/**
 * Extract bearer token from Authorization header
 * @param {string} authHeader - Authorization header value
 * @returns {string|null} - Token or null
 */
function extractBearerToken(authHeader) {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
}

module.exports = {
  verifyToken,
  extractBearerToken,
  base64UrlDecode
};
