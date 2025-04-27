from fastapi import Depends, HTTPException, Header
import jwt
from dotenv import load_dotenv
import os

load_dotenv()

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
if not SUPABASE_JWT_SECRET:
    raise Exception("Missing required environment variable: SUPABASE_JWT_SECRET")

async def get_current_user(authorization: str = Header(...)):
    """
    Extract user info from Authorization Bearer token.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Invalid auth token format.")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")
    
    return payload  # Contains user_id, email, role, etc.
