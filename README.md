# Task Overview
A FastAPI microservice secures endpoints with OAuth2 token authentication and role-based access control. However, all requests to protected endpoints are currently failing with 401 Unauthorized, even with valid tokens. Your role is to restore secure authentication and ensure appropriate gated access for users.

# Guidance
- The app uses OAuth2PasswordBearer, JWT tokens, and SQLAlchemy for user lookups
- User and token data are managed securely and in alignment with FastAPI authentication standards
- The database is pre-seeded with test users and correct password hashes
- Review the authentication and authorization flow for potential logic issues

# Objectives
- Diagnose and fix the bug causing all token-authenticated requests to be rejected by protected endpoints
- Ensure users with valid tokens can access protected resources
- Maintain appropriate 401 rejections for requests with invalid, missing, or expired tokens

# How to Verify
- Send a request to the token endpoint to obtain an access token using correct credentials
- Access a protected endpoint with a valid token and confirm successful access
- Verify that requests with no or invalid tokens are properly rejected with 401
