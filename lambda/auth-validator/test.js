'use strict';

const { verifyToken, extractBearerToken, base64UrlDecode } = require('./jwt');
const { handler } = require('./index');
const crypto = require('crypto');

// Test secret
const TEST_SECRET = 'test-secret-key-32-bytes-long!!';

/**
 * Create a test JWT token
 */
function createTestToken(payload, secret, expiresInSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Create a CloudFront event for testing
 */
function createEvent(uri, authHeader) {
  const event = {
    Records: [{
      cf: {
        request: {
          uri: uri,
          headers: {},
          origin: {
            custom: {
              customHeaders: {
                'x-jwt-secret': [{ value: TEST_SECRET }]
              }
            }
          }
        }
      }
    }]
  };

  if (authHeader) {
    event.Records[0].cf.request.headers['authorization'] = [{ value: authHeader }];
  }

  return event;
}

// Test results
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`❌ ${name}: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

function assertNotNull(value, message) {
  if (value === null || value === undefined) {
    throw new Error(`${message}: expected non-null value`);
  }
}

function assertNull(value, message) {
  if (value !== null) {
    throw new Error(`${message}: expected null, got ${value}`);
  }
}

// JWT Tests
console.log('\n=== JWT Module Tests ===\n');

test('verifyToken: valid token', () => {
  const token = createTestToken({ user_id: '123', email: 'test@example.com' }, TEST_SECRET);
  const payload = verifyToken(token, TEST_SECRET);
  assertNotNull(payload, 'payload');
  assertEqual(payload.user_id, '123', 'user_id');
  assertEqual(payload.email, 'test@example.com', 'email');
});

test('verifyToken: expired token', () => {
  const token = createTestToken({ user_id: '123' }, TEST_SECRET, -1);
  const payload = verifyToken(token, TEST_SECRET);
  assertNull(payload, 'expired token should return null');
});

test('verifyToken: invalid signature', () => {
  const token = createTestToken({ user_id: '123' }, TEST_SECRET);
  const payload = verifyToken(token, 'wrong-secret');
  assertNull(payload, 'invalid signature should return null');
});

test('verifyToken: malformed token', () => {
  const payload = verifyToken('not.a.valid.token', TEST_SECRET);
  assertNull(payload, 'malformed token should return null');
});

test('verifyToken: empty token', () => {
  const payload = verifyToken('', TEST_SECRET);
  assertNull(payload, 'empty token should return null');
});

test('extractBearerToken: valid header', () => {
  const token = extractBearerToken('Bearer abc123');
  assertEqual(token, 'abc123', 'token');
});

test('extractBearerToken: missing Bearer prefix', () => {
  const token = extractBearerToken('abc123');
  assertNull(token, 'missing Bearer should return null');
});

test('extractBearerToken: empty header', () => {
  const token = extractBearerToken('');
  assertNull(token, 'empty header should return null');
});

// Handler Tests
console.log('\n=== Handler Tests ===\n');

test('handler: public path /health', (done) => {
  const event = createEvent('/health', null);
  handler(event, {}, (err, result) => {
    assertEqual(result.uri, '/health', 'should pass through');
  });
});

test('handler: public path /api/v1/auth/login', () => {
  const event = createEvent('/api/v1/auth/login', null);
  handler(event, {}, (err, result) => {
    assertEqual(result.uri, '/api/v1/auth/login', 'should pass through');
  });
});

test('handler: protected path without token', () => {
  const event = createEvent('/api/v1/users', null);
  handler(event, {}, (err, result) => {
    assertEqual(result.status, '401', 'should return 401');
  });
});

test('handler: protected path with valid token', () => {
  const token = createTestToken({
    user_id: 'user-123',
    email: 'test@example.com',
    roles: ['admin'],
    sections: ['dashboard', 'settings']
  }, TEST_SECRET);
  
  const event = createEvent('/api/v1/users', `Bearer ${token}`);
  handler(event, {}, (err, result) => {
    assertEqual(result.uri, '/api/v1/users', 'should pass through');
    assertEqual(result.headers['x-user-id'][0].value, 'user-123', 'x-user-id header');
    assertEqual(result.headers['x-user-email'][0].value, 'test@example.com', 'x-user-email header');
    assertEqual(result.headers['x-user-roles'][0].value, 'admin', 'x-user-roles header');
    assertEqual(result.headers['x-user-sections'][0].value, 'dashboard,settings', 'x-user-sections header');
  });
});

test('handler: protected path with invalid token', () => {
  const event = createEvent('/api/v1/users', 'Bearer invalid-token');
  handler(event, {}, (err, result) => {
    assertEqual(result.status, '401', 'should return 401');
  });
});

test('handler: protected path with expired token', () => {
  const token = createTestToken({ user_id: '123' }, TEST_SECRET, -1);
  const event = createEvent('/api/v1/users', `Bearer ${token}`);
  handler(event, {}, (err, result) => {
    assertEqual(result.status, '401', 'should return 401');
  });
});

// Summary
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
