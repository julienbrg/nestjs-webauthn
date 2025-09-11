# WebAuthn Implementation

A NestJS-based WebAuthn authentication service with TypeScript support for passwordless authentication using FIDO2/WebAuthn standards.

## Features

- Passwordless authentication using biometrics, security keys, or platform authenticators
- Registration and verification of WebAuthn credentials
- In-memory storage for development (replace with database for production)
- TypeScript support with comprehensive type definitions
- CORS configuration for frontend integration

## Multi-Device Support Limitations

This implementation supports **same-platform multi-device authentication** with the following constraints:

### Supported Scenarios
- **Same Ecosystem Sync**: Passkeys registered on iPhone work on Mac (via iCloud Keychain)
- **Same Platform**: Google Password Manager syncing between Android devices
- **Hardware Keys**: Physical security keys work across any device

### Unsupported Scenarios
- **Cross-Platform**: Passkeys registered on iOS will not work on Android devices
- **Different Ecosystems**: Apple passkeys cannot authenticate on Google/Microsoft platforms
- **Mixed Environments**: Enterprise environments with mixed device types may require multiple registrations

### Technical Limitation
Cross-platform authentication fails because synced passkeys may present different credential IDs. The WebAuthn specification requires exact credential matching for verification, which this implementation enforces for security.

## API Endpoints

### Registration
- `POST /webauthn/register/begin` - Start passkey registration
- `POST /webauthn/register/complete` - Complete passkey registration

### Authentication
- `POST /webauthn/authenticate/begin` - Start passkey authentication
- `POST /webauthn/authenticate/complete` - Complete passkey authentication

### Utilities
- `GET /webauthn/user?userId={id}` - Get user information
- `GET /webauthn/health` - Service health check

## Frontend Integration (Next.js TypeScript)

### Installation

```bash
npm install @simplewebauthn/browser
```

### Environment Configuration

```typescript
// config/webauthn.ts
export const WEBAUTHN_CONFIG = {
  API_BASE: process.env.NEXT_PUBLIC_WEBAUTHN_API || 'http://localhost:3000',
  TIMEOUT: 60000, // 60 seconds
};
```

### Types

```typescript
// types/webauthn.ts
interface WebAuthnUser {
  id: string;
  username: string;
  email: string;
  hasAuthenticators: boolean;
  authenticatorCount: number;
}

interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}
```

### Registration Implementation

```typescript
// hooks/useWebAuthn.ts
import { startRegistration } from '@simplewebauthn/browser';

export const useWebAuthn = () => {
  const register = async (userId: string, username: string) => {
    try {
      // Begin registration
      const beginResponse = await fetch(`${WEBAUTHN_CONFIG.API_BASE}/webauthn/register/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, username }),
      });

      const beginResult: ApiResponse = await beginResponse.json();
      if (!beginResult.success) throw new Error(beginResult.message);

      // Start WebAuthn registration
      const attResp = await startRegistration(beginResult.data.options);

      // Complete registration
      const completeResponse = await fetch(`${WEBAUTHN_CONFIG.API_BASE}/webauthn/register/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, response: attResp }),
      });

      const completeResult: ApiResponse<{ user: WebAuthnUser }> = await completeResponse.json();
      if (!completeResult.success) throw new Error(completeResult.message);

      return completeResult.data.user;
    } catch (error) {
      console.error('Registration failed:', error);
      throw error;
    }
  };

  return { register };
};
```

### Authentication Implementation

```typescript
// hooks/useWebAuthn.ts (continued)
import { startAuthentication } from '@simplewebauthn/browser';

const authenticate = async (userId: string) => {
  try {
    // Begin authentication
    const beginResponse = await fetch(`${WEBAUTHN_CONFIG.API_BASE}/webauthn/authenticate/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId }),
    });

    const beginResult: ApiResponse = await beginResponse.json();
    if (!beginResult.success) throw new Error(beginResult.message);

    // Start WebAuthn authentication
    const authResp = await startAuthentication(beginResult.data.options);

    // Complete authentication
    const completeResponse = await fetch(`${WEBAUTHN_CONFIG.API_BASE}/webauthn/authenticate/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, response: authResp }),
    });

    const completeResult: ApiResponse<{ user: WebAuthnUser }> = await completeResponse.json();
    if (!completeResult.success) throw new Error(completeResult.message);

    return completeResult.data.user;
  } catch (error) {
    console.error('Authentication failed:', error);
    throw error;
  }
};
```

### Component Example

```typescript
// components/WebAuthnLogin.tsx
import { useState } from 'react';
import { useWebAuthn } from '../hooks/useWebAuthn';

export const WebAuthnLogin = () => {
  const [userId, setUserId] = useState('');
  const [username, setUsername] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { register, authenticate } = useWebAuthn();

  const handleRegister = async () => {
    setIsLoading(true);
    try {
      const user = await register(userId, username);
      console.log('Registration successful:', user);
    } catch (error) {
      console.error('Registration error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthenticate = async () => {
    setIsLoading(true);
    try {
      const user = await authenticate(userId);
      console.log('Authentication successful:', user);
    } catch (error) {
      console.error('Authentication error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <input 
        value={userId} 
        onChange={(e) => setUserId(e.target.value)}
        placeholder="User ID"
      />
      <input 
        value={username} 
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <button onClick={handleRegister} disabled={isLoading}>
        Register Passkey
      </button>
      <button onClick={handleAuthenticate} disabled={isLoading}>
        Authenticate
      </button>
    </div>
  );
};
```

### Error Handling

```typescript
// utils/webauthn-errors.ts
export const getWebAuthnErrorMessage = (error: any): string => {
  if (error.name === 'NotAllowedError') {
    return 'User cancelled the operation or the operation timed out';
  }
  if (error.name === 'SecurityError') {
    return 'Security error - check HTTPS and domain configuration';
  }
  if (error.name === 'NotSupportedError') {
    return 'WebAuthn is not supported on this device/browser';
  }
  return error.message || 'An unknown error occurred';
};
```

## Environment Variables

```bash
# Backend (.env)
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=WebAuthn Demo
WEBAUTHN_ORIGIN=http://localhost:3000

# Frontend (.env.local)
NEXT_PUBLIC_WEBAUTHN_API=http://localhost:3000
```

## Browser Support

- Chrome 67+ (all platforms)
- Firefox 60+ (all platforms)
- Safari 14+ (macOS, iOS)
- Edge 18+ (Windows)

## Production Considerations

- Replace in-memory storage with persistent database
- Implement proper session management
- Add rate limiting for authentication attempts
- Configure proper HTTPS and domain settings
- Implement user handle verification for enhanced cross-device support
- Add fallback authentication methods (email, SMS)
- Implement proper error logging and monitoring

## Security Notes

- All WebAuthn operations require HTTPS in production
- RP ID must match the domain exactly
- Origin must be configured correctly for CORS
- Credential verification requires exact credential ID matching
- Consider implementing additional user verification for new devices

## Support

Feel free to reach out to [Julien](https://github.com/julienbrg) on [Farcaster](https://warpcast.com/julien-), [Element](https://matrix.to/#/@julienbrg:matrix.org), [Status](https://status.app/u/iwSACggKBkp1bGllbgM=#zQ3shmh1sbvE6qrGotuyNQB22XU5jTrZ2HFC8bA56d5kTS2fy), [Telegram](https://t.me/julienbrg), [Twitter](https://twitter.com/julienbrg), [Discord](https://discordapp.com/users/julienbrg), or [LinkedIn](https://www.linkedin.com/in/julienberanger/).