from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import Callable

security = HTTPBearer()

ROLES = {
    'analyst':   ['read:alerts', 'write:verdicts', 'read:incidents'],
    'senior':    ['read:alerts', 'write:verdicts', 'read:incidents',
                  'write:responses', 'read:settings'],
    'admin':     ['*']
}

def require_permission(permission: str) -> Callable:
    def checker(credentials: HTTPAuthorizationCredentials = Security(security)):
        token = credentials.credentials
        try:
            payload = jwt.decode(token, "SUPER_SECRET_KEY", algorithms=["HS256"])
            role = payload.get('role', 'analyst')
            if role not in ROLES:
                raise HTTPException(403, "Invalid role")
                
            if '*' not in ROLES[role] and permission not in ROLES[role]:
                raise HTTPException(403, f"Insufficient permissions: requires {permission}")
                
            return payload
        except jwt.PyJWTError:
            raise HTTPException(401, "Invalid or expired token")
            
    return checker

def create_demo_token(role: str = 'admin') -> str:
    """Create a temporary JWT token for testing."""
    return jwt.encode({"sub": "test_user", "role": role}, "SUPER_SECRET_KEY", algorithm="HS256")
