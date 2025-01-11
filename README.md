# NestJS Authentication Service

A robust authentication service built with NestJS, featuring local authentication, JWT tokens, and Google OAuth2.0 integration.

## Features

- 🔐 Local Authentication with Email/Password
- 🎫 JWT-based Authentication with Access & Refresh Tokens
- 🔄 Token Refresh Mechanism
- 🌐 Google OAuth2.0 Integration
- 🍪 Secure HTTP-only Cookie Management
- 🗄️ MongoDB Integration with Mongoose
- ✨ Input Validation using class-validator
- 🔒 Password Hashing with bcrypt

## Prerequisites

- Node.js (v14 or higher)
- pnpm
- MongoDB
- Google OAuth2.0 credentials (for Google authentication)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd nestjs-auth
```

2. Install dependencies:

```bash
pnpm install
```

3. Create a `.env` file in the root directory with the following variables:

```env
# NODE_ENV
NODE_ENV=development

# MongoDB
MONGODB_URI=mongodb://localhost:27017/your-database

# JWT
JWT_ACCESS_TOKEN_SECRET=your-access-token-secret
JWT_REFRESH_TOKEN_SECRET=your-refresh-token-secret
JWT_ACCESS_TOKEN_EXPIRATION_MS=900000 # 15 minutes
JWT_REFRESH_TOKEN_EXPIRATION_MS=604800000 # 7 days

# Google OAuth
GOOGLE_AUTH_CLIENT_ID=your-google-client-id
GOOGLE_AUTH_CLIENT_SECRET=your-google-client-secret
GOOGLE_AUTH_REDIRECT_URI=http://localhost:3000/auth/google/callback
AUTH_UI_REDIRECT=http://localhost:4200 # Your frontend URL
```

## Running the Application

```bash
# Development
$ pnpm run start

# Watch mode
$ pnpm run start:dev

# Production mode
$ pnpm run start:prod
```

## Docker

The project includes a Docker Compose configuration for MongoDB:

```bash
docker compose up
```

## API Endpoints

### Authentication

- POST /auth/login
  - Local authentication with email/password
  - Returns JWT tokens in HTTP-only cookies
- POST /auth/refresh
  - Refresh access token using refresh token
  - Requires valid refresh token cookie
- GET /auth/google
  - Initiate Google OAuth2.0 authentication
- GET /auth/google/callback
  - Google OAuth2.0 callback handler
  - Returns JWT tokens in HTTP-only cookies

### Users

- POST /users
  - Create new user
  - Body: { email: string, password: string }
- GET /users
  - Get all users
  - Requires authentication

## Testing

```bash
# Unit tests
$ pnpm run test

# Watch mode
$ pnpm run test:watch

# Test coverage
$ pnpm run test:cov
```

## Security Features

- Passwords are hashed using bcrypt
- JWT tokens are stored in HTTP-only cookies
- Input validation using class-validator
- Strong password requirements
- Refresh token rotation
- Protected routes using Guards

## Project Structure

```
src/
├── auth/ # Authentication module
│ ├── guards/ # Authentication guards
│ ├── strategies/ # Passport strategies
│ └── decorators/ # Custom decorators
├── users/ # Users module
│ ├── dto/ # Data transfer objects
│ └── schema/ # Mongoose schemas
└── main.ts # Application entry point
```

## Architecture Deep Dive

### Modules

#### 1. AuthModule

```typescript
@Module({
imports: [UsersModule, PassportModule, JwtModule],
providers: [AuthService, LocalStrategy, JwtStrategy, JwtRefreshStrategy, GoogleStrategy],
})
```

- **Purpose**: Handles all authentication-related functionality
- **Dependencies**: UsersModule, PassportModule, JwtModule
- **Advantages**:
  - Centralized authentication logic
  - Modular and reusable
  - Easy to extend with new strategies
- **Usage**:
  ```typescript
  imports: [AuthModule];
  ```

#### 2. UsersModule

```typescript
@Module({
imports: [MongooseModule.forFeature([{ name: User.name, schema: UserSchema }])],
providers: [UsersService],
exports: [UsersService],
})
```

- **Purpose**: Manages user-related operations
- **Advantages**:
  - Separation of user management logic
  - Reusable user operations
  - Clean database abstraction
- **Usage**:
  ```typescript
  imports: [UsersModule];
  ```

### Authentication Strategies

#### 1. Local Strategy

```typescript
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy)
```

- **Purpose**: Email/password authentication
- **Advantages**:
  - Simple and familiar authentication flow
  - Easy to implement and maintain
- **Disadvantages**:
  - Requires password storage
  - Less secure than OAuth or passwordless options
- **Usage**:
  ```typescript
  @UseGuards(LocalAuthGuard)
  async login(@Request() req) {}
  ```

#### 2. JWT Strategy

```typescript
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy)
```

- **Purpose**: Token-based authentication
- **Advantages**:
  - Stateless authentication
  - Scalable
  - Cross-domain support
- **Disadvantages**:
  - Token size
  - Can't revoke individual tokens without additional logic
- **Usage**:
  ```typescript
  @UseGuards(JwtAuthGuard)
  async getProtectedResource() {}
  ```

#### 3. JWT Refresh Strategy

```typescript
@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh')
```

- **Purpose**: Handle refresh token rotation
- **Advantages**:
  - Enhanced security
  - Better user experience
  - Shorter access token lifetimes
- **Disadvantages**:
  - More complex implementation
  - Requires token storage
- **Usage**:
  ```typescript
  @UseGuards(JwtRefreshAuthGuard)
  async refresh() {}
  ```

#### 4. Google Strategy

```typescript
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy)
```

- **Purpose**: Google OAuth2.0 authentication
- **Advantages**:
  - No password management
  - Trusted third-party authentication
  - Access to Google user data
- **Disadvantages**:
  - Dependency on external service
  - Requires additional setup
- **Usage**:
  ```typescript
  @UseGuards(GoogleAuthGuard)
  async googleAuth() {}
  ```

### Guards

#### 1. LocalAuthGuard

- **Purpose**: Protects email/password login routes
- **Usage**:
  ```typescript
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login() {}
  ```

#### 2. JwtAuthGuard

- **Purpose**: Protects routes requiring valid JWT
- **Usage**:
  ```typescript
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile() {}
  ```

#### 3. JwtRefreshAuthGuard

- **Purpose**: Protects refresh token endpoints
- **Usage**:
  ```typescript
  @UseGuards(JwtRefreshAuthGuard)
  @Post('refresh')
  async refresh() {}
  ```

#### 4. GoogleAuthGuard

- **Purpose**: Handles Google OAuth2.0 flow
- **Usage**:
  ```typescript
  @UseGuards(GoogleAuthGuard)
  @Get('google')
  async googleAuth() {}
  ```

### Best Practices

1. **Token Storage**

   - Store tokens in HTTP-only cookies
   - Implement CSRF protection
   - Use secure and SameSite cookie options

2. **Security Headers**

   ```typescript
   app.use(helmet());
   app.enableCors({
     origin: true,
     credentials: true,
   });
   ```

3. **Rate Limiting**

   ```typescript
   app.use(
     rateLimit({
       windowMs: 15 * 60 * 1000,
       max: 100,
     }),
   );
   ```

4. **Validation**
   ```typescript
   app.useGlobalPipes(
     new ValidationPipe({
       whitelist: true,
       forbidNonWhitelisted: true,
     }),
   );
   ```

### Common Flows

#### 1. Local Authentication

1. User submits email/password
2. LocalStrategy validates credentials
3. Generate access and refresh tokens
4. Set tokens in HTTP-only cookies
5. Return user data

#### 2. Token Refresh

1. Client sends refresh token
2. JwtRefreshStrategy validates token
3. Generate new access and refresh tokens
4. Update stored refresh token
5. Set new tokens in cookies

#### 3. Google OAuth

1. User initiates Google login
2. Redirect to Google consent screen
3. Google redirects back with code
4. Exchange code for Google tokens
5. Create/update user and generate tokens

## Request Flow Examples

### Local Authentication Flow

```typescript
// 1. Login Request
POST /auth/login
Body: {
"email": "user@example.com",
"password": "StrongPass123!"
}
// 2. Successful Response
HTTP/1.1 200 OK
Set-Cookie: Authentication=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
Set-Cookie: Refresh=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
```

### Token Refresh Flow

```typescript
// 1. Refresh Request
POST /auth/refresh
Cookie: Refresh=eyJhbGc...
// 2. Successful Response
HTTP/1.1 200 OK
Set-Cookie: Authentication=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
Set-Cookie: Refresh=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
```

### Google OAuth Flow

```typescript
AUTH_UI_REDIRECT=https://accounts.google.com/o/oauth2/auth?client_id=...
// 1. Initiate Google Login
GET /auth/google
// 2. Google Callback
GET /auth/google/callback?code=4/0AfJohXn...
// 3. Successful Response
HTTP/1.1 302 Found
Set-Cookie: Authentication=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
Set-Cookie: Refresh=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
Location: ${AUTH_UI_REDIRECT}
```

## Error Handling

The service implements standardized error responses:

```typescript
{
"statusCode": number,
"message": string,
"error": string,
"timestamp": string,
"path": string
}
```

Common error scenarios:

- 401 Unauthorized: Invalid credentials
- 403 Forbidden: Valid token but insufficient permissions
- 422 Unprocessable Entity: Invalid input data
- 429 Too Many Requests: Rate limit exceeded

## Environment Setup Guide

### Development Environment

1. Install MongoDB Community Edition
2. Set up Google OAuth2.0 credentials:
   - Go to Google Cloud Console
   - Create a new project
   - Enable Google+ API
   - Configure OAuth consent screen
   - Create OAuth 2.0 credentials
   - Add authorized redirect URIs

### Production Considerations

- Use strong JWT secrets
- Configure appropriate cookie settings
- Set up CORS properly
- Implement rate limiting
- Use HTTPS
- Configure MongoDB security

## Performance Optimization

- JWT token size optimization
- Database indexing
- Caching strategies
- Rate limiting configuration
- Connection pooling

## Debugging

```bash
# Debug mode with auto-reload
$ pnpm run start:debug
# Debug tests
$ pnpm run test:debug
```

Use Chrome DevTools for debugging:

1. Open chrome://inspect
2. Click on "Open dedicated DevTools for Node"

## Troubleshooting

Common issues and solutions:

### MongoDB Connection Issues

```bash
# Check MongoDB status
$ mongosh
```

### JWT Token Issues

- Verify token expiration times
- Check cookie settings
- Ensure correct secret keys

### Google OAuth Issues

- Verify redirect URI configuration
- Check Google Console credentials
- Validate scope settings

## API Documentation

For detailed API documentation, run the server and visit:

```bash
http://localhost:3000/api
```

## Deployment

### Docker Deployment

```dockerfile
# Full application deployment
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```bash
# Build Docker image
docker build -t nestjs-auth .
# Push to Docker Hub
docker push your-dockerhub-username/nestjs-auth
# Deploy to Kubernetes
kubectl apply -f kubernetes-deployment.yaml
```

### Manual Deployment

1. Build the application

```bash
pnpm run build
```

2. Set production environment variables

3. Run the application

```bash
pnpm run start:prod
```

## Monitoring

### Health Checks

- GET /health - Basic health check
- GET /health/db - Database health
- GET /health/detailed - Detailed system status

### Metrics

- Request rate
- Error rate
- Authentication success/failure rate
- Token refresh rate
- Average response time

## Security Deep Dive

### Token Storage: Cookies vs localStorage

#### Why HTTP-Only Cookies?

1. **Protection Against XSS Attacks**

   - HTTP-Only cookies cannot be accessed by JavaScript
   - Even if an attacker injects malicious scripts (XSS), they cannot steal the tokens
   - `localStorage` and `sessionStorage` are accessible by JavaScript, making them vulnerable to XSS

2. **Automatic CSRF Protection**
   ```typescript
   // Setting secure cookies in NestJS
   response.cookie('Authentication', token, {
     httpOnly: true,
     secure: true,
     sameSite: 'strict',
     path: '/',
   });
   ```

#### Why Not localStorage?

1. **XSS Vulnerabilities**

   ```javascript
   // Vulnerable localStorage example
   localStorage.setItem('token', 'your-jwt-token'); // Bad practice!

   // If attacker injects:
   <script>sendToMaliciousServer(localStorage.getItem('token'));</script>;
   // Your token is compromised!
   ```

2. **Automatic Token Transmission**
   - Cookies are automatically sent with requests to the same domain
   - `localStorage` requires manual token attachment to requests
   ```javascript
   // Manual attachment needed with localStorage
   fetch('/api/data', {
     headers: {
       Authorization: `Bearer ${localStorage.getItem('token')}`,
     },
   });
   ```

### Cookie Security Options

1. **HttpOnly**

   - Prevents JavaScript access
   - Mitigates XSS attacks

   ```typescript
   httpOnly: true;
   ```

2. **Secure**

   - Ensures cookies are only sent over HTTPS
   - Prevents man-in-the-middle attacks

   ```typescript
   secure: true;
   ```

3. **SameSite**

   - Controls how cookies are sent with cross-site requests
   - Protects against CSRF attacks

   ```typescript
   sameSite: 'strict'; // or 'lax'
   ```

4. **Domain and Path**
   - Limits cookie scope
   - Reduces attack surface
   ```typescript
   domain: 'your-domain.com',
   path: '/api'
   ```

### CSRF Protection

Even with HTTP-Only cookies, CSRF attacks are possible. Mitigate them by:

1. **SameSite Cookie Attribute**

   ```typescript
   sameSite: 'strict';
   ```

2. **CSRF Tokens**

   ```typescript
   // Generate CSRF token
   app.use(csurf());

   // Include in forms
   <input type="hidden" name="_csrf" value="<%= csrfToken %>">
   ```

### Token Security Best Practices

1. **Short-lived Access Tokens**

   ```typescript
   // Configure short expiration
   const accessToken = this.jwtService.sign(payload, {
     expiresIn: '15m', // 15 minutes
   });
   ```

2. **Refresh Token Rotation**

   - Issue new refresh token with each refresh
   - Invalidate old refresh tokens

   ```typescript
   async refresh(oldRefreshToken: string) {
     // Invalidate old refresh token
     await this.invalidateRefreshToken(oldRefreshToken);

     // Generate new tokens
     const [accessToken, refreshToken] = await this.generateTokens();

     return { accessToken, refreshToken };
   }
   ```

3. **Token Revocation Strategy**
   ```typescript
   // Store token hashes in database
   async revokeToken(token: string) {
     const hash = await bcrypt.hash(token, 10);
     await this.tokenBlacklist.create({ hash });
   }
   ```

### Additional Security Measures

1. **Rate Limiting**

   ```typescript
   app.use(
     rateLimit({
       windowMs: 15 * 60 * 1000, // 15 minutes
       max: 100, // limit each IP to 100 requests per windowMs
       message: 'Too many requests from this IP, please try again later',
     }),
   );
   ```

2. **Password Hashing**

   ```typescript
   // Use bcrypt with appropriate rounds
   const hashedPassword = await bcrypt.hash(password, 12);
   ```

3. **Input Validation**

   ```typescript
   app.useGlobalPipes(
     new ValidationPipe({
       whitelist: true,
       forbidNonWhitelisted: true,
       transform: true,
     }),
   );
   ```

4. **Security Headers**
   ```typescript
   app.use(helmet());
   ```

### Security Checklist

- [ ] Use HTTP-Only cookies for token storage
- [ ] Implement CSRF protection
- [ ] Enable CORS with appropriate settings
- [ ] Set secure cookie attributes
- [ ] Implement rate limiting
- [ ] Use HTTPS in production
- [ ] Implement proper password hashing
- [ ] Validate all input data
- [ ] Set security headers
- [ ] Implement token rotation
- [ ] Monitor for suspicious activities

## Frontend Integration Guide

### Integration with React.js

#### 1. CORS Configuration (Backend)

```typescript
// main.ts
app.enableCors({
  origin: 'http://localhost:3000', // Your React app URL
  credentials: true, // Important for cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
});
```

#### 2. API Client Setup (Frontend)

```typescript
// api/axios.ts
import axios from 'axios';
const api = axios.create({
  baseURL: 'http://localhost:4000', // Your NestJS API URL
  withCredentials: true, // Important for cookies
  headers: {
    'Content-Type': 'application/json',
  },
});
export default api;
```

#### 3. Authentication Hook Example

```typescript
// hooks/useAuth.ts
import { useState } from 'react';
import api from '../api/axios';
export const useAuth = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const login = async (email: string, password: string) => {
    try {
      setLoading(true);
      const response = await api.post('/auth/login', { email, password });
      setUser(response.data);
      return response.data;
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
      throw err;
    } finally {
      setLoading(false);
    }
  };
  const logout = async () => {
    try {
      await api.post('/auth/logout');
      setUser(null);
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
      throw err;
    }
  };
  const refreshToken = async () => {
    try {
      const response = await api.post('/auth/refresh');
      return response.data;
    } catch (err) {
      setError(err.response?.data?.message || 'An error occurred');
      throw err;
    }
  };
  return { user, loading, error, login, logout, refreshToken };
};
```

#### 4. Protected Route Component

```typescript
// components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
export const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) {
    return <div>Loading...</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
};
```

#### 5. Login Component Example

```typescript
// components/Login.tsx
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
export const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, error, loading } = useAuth();
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
    await login(email, password);
    // Redirect or update UI
    } catch (err) {
    // Handle error
    }
  };
  return (
  <form onSubmit={handleSubmit}>
    <input
      type="email"
      value={email}
      onChange={(e) => setEmail(e.target.value)}
    />
    <input
      type="password"
      value={password}
      onChange={(e) => setPassword(e.target.value)}
    />
    <button type="submit" disabled={loading}>
    {loading ? 'Loading...' : 'Login'}
    </button>
    {error && <div className="error">{error}</div>}
  </form>
  );
};
```

### Integration with Next.js

#### 1. API Route Handler (Optional for BFF pattern)

```typescript
// pages/api/auth/[...auth].ts
import { NextApiRequest, NextApiResponse } from 'next';
import httpProxy from 'http-proxy';
const proxy = httpProxy.createProxyServer();
const API_URL = process.env.API_URL;
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  return new Promise((resolve, reject) => {
    proxy.web(req, res, { target: API_URL, changeOrigin: true }, (err) => {
      if (err) {
        return reject(err);
      }
      resolve(undefined);
    });
  });
}
```

#### 2. Authentication Context

```typescript
// contexts/AuthContext.tsx
import { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/axios';
const AuthContext = createContext({});

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    checkUser();
  }, []);
  const checkUser = async () => {
    try {
      const response = await api.get('/auth/me');
      setUser(response.data);
    } catch (err) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };
  // ... auth methods
  return (
    <AuthContext.Provider value={{ user, loading, / other methods / }}>
      {children}
    </AuthContext.Provider>
  );
}
export const useAuth = () => useContext(AuthContext);
```

#### 3. Middleware for Protected Routes

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const authCookie = request.cookies.get('Authentication');
  if (!authCookie && !request.nextUrl.pathname.startsWith('/auth')) {
    return NextResponse.redirect(new URL('/auth/login', request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
  /
  Match all request paths except:
  - auth (public routes)
  - api (API routes)
  - static files
  /
  '/((?!auth|api|next/static|_next/image|favicon.ico).)',
  ],
};
```

#### 4. Example Page with SSR Authentication

```typescript
// pages/protected.tsx
import { GetServerSideProps } from 'next';
import { useAuth } from '../contexts/AuthContext';
export const getServerSideProps: GetServerSideProps = async (context) => {
  const { req } = context;
  const authCookie = req.cookies['Authentication'];
  if (!authCookie) {
    return {
      redirect: {
        destination: '/auth/login',
        permanent: false,
      },
    };
  }
  return {
    props: {},
  };
};

export default function ProtectedPage() {
  const { user } = useAuth();
  return <div>Protected Content for {user?.email}</div>;
}
```

### Common Integration Patterns

1. **Error Handling**

```typescript
// interceptors/error.ts
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized error
      try {
        await api.post('/auth/refresh');
        return api(error.config);
      } catch (err) {
        // Redirect to login
      }
    }
    return Promise.reject(error);
  },
);
```

2. **Token Refresh Logic**

```typescript
// utils/refreshToken.ts
let refreshPromise = null;
export const refreshTokenIfNeeded = async () => {
  if (!refreshPromise) {
    refreshPromise = api.post('/auth/refresh').finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
};
```

3. **Google OAuth Integration**

```typescript
// components/GoogleLogin.tsx
export const GoogleLogin = () => {
  const handleGoogleLogin = () => {
    window.location.href = 'http://localhost:4000/auth/google';
  };
  return (
    <button onClick={handleGoogleLogin}>
    Login with Google
    </button>
  );
};
```

These integration examples provide a solid foundation for connecting your NestJS backend with React or Next.js frontends. Remember to:

- Configure CORS properly
- Handle token refresh logic
- Implement proper error handling
- Secure routes appropriately
- Manage authentication state
- Handle SSR considerations (for Next.js)

## Common Use Cases and Examples

### 1. Role-Based Authorization

```typescript
// Implementing roles
@SetMetadata('roles', ['admin'])
@UseGuards(JwtAuthGuard, RolesGuard)
@Get('admin-only')
adminRoute() {
return 'Admin only content';
}
```

### 2. Custom Decorators

```typescript
// Create a custom user decorator
export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

### 3. Custom Guards

```typescript
// Implementing a custom guard
@Injectable()
export class CustomGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    return request.user && request.user.role === 'admin';
  }
}
```

### 4. Custom Interceptors

```typescript
// Implementing a custom interceptor
@Injectable()
export class CustomInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(map((data) => ({ data })));
  }
}
```

### 5. Custom Filters

```typescript
// Implementing a custom filter
@Injectable()
export class CustomFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    response.status(exception.getStatus()).json({ message: exception.message });
  }
}
```

### 6. Custom Pipes

```typescript
// Implementing a custom pipe
@Injectable()
export class CustomPipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    return value;
  }
}
```

```typescript
// Using the custom pipe
@UsePipes(CustomPipe)
@Get('custom-pipe')
customPipeRoute(@Query('data') data: string) {
  return { data };
}
```

### 7. Custom Middleware

```typescript
// Implementing a custom middleware
@Injectable()
export class CustomMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Custom logic here
    next();
  }
}
```

### 8. Custom Exception Filters

```typescript
// Implementing a custom exception filter
@Injectable()
export class CustomExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    response.status(exception.getStatus()).json({ message: exception.message });
  }
}
```

### 9. Multiple Authentication Methods

```typescript
@UseGuards(JwtAuthGuard, ApiKeyAuthGuard)
@Get('protected')
protectedRoute() {
return 'Protected content';
}
```

## Development Tools

### 1. Recommended VSCode Extensions

- NestJS Snippets
- Prettier
- ESLint
- MongoDB for VS Code
- Thunder Client (API testing)

### 2. Debugging Tools

- MongoDB Compass
- Postman/Insomnia
- Chrome DevTools
- JWT Debugger (jwt.io)

## Performance Tips

### 1. Database Optimization

```typescript
// Create indexes for frequently queried fields
@Schema({
  timestamps: true,
  indexes: [{ email: 1, unique: true }],
})
export class User {}
```

### 2. Caching Strategies

```typescript
// Implement caching for frequently accessed data
@UseInterceptors(CacheInterceptor)
@Get('users')
getUsers() {
  return this.usersService.findAll();
}
```

### 3. Connection Pooling

```typescript
// MongoDB connection pooling
MongooseModule.forRootAsync({
  useFactory: () => ({
    uri: process.env.MONGODB_URI,
    maxPoolSize: 10,
    minPoolSize: 5,
  }),
});
```

## FAQ

### Common Questions

1. **Q: Why use refresh tokens?**
   A: Refresh tokens allow for shorter-lived access tokens while maintaining user sessions, improving security.

2. **Q: How to handle token expiration?**
   A: Implement automatic token refresh using interceptors and handle 401 responses.

3. **Q: Can I use this with microservices?**
   A: Yes, the authentication service can be adapted for microservices architecture using JWT validation.

### Known Issues

1. **Token Refresh Race Condition**

   - Solution: Implement refresh token rotation with a grace period

2. **CORS Issues with Cookies**
   - Solution: Ensure proper CORS configuration with credentials

## Roadmap

### Upcoming Features

- [ ] Multi-factor Authentication
- [ ] OAuth2.0 Provider Implementation
- [ ] Session Management
- [ ] Audit Logging
- [ ] Rate Limiting Improvements

### Future Improvements

1. **Security Enhancements**

   - Hardware token support
   - Biometric authentication
   - Advanced rate limiting

2. **Performance Optimizations**
   - Caching improvements
   - Database optimization
   - Connection pooling

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.
