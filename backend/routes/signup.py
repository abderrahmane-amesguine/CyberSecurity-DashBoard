from fastapi import APIRouter, Body
from pydantic import BaseModel
from dependencies import supabase
import uuid

router = APIRouter()

class AdminSignupRequest(BaseModel):
    company_name: str
    admin_email: str

class UserSignupRequest(BaseModel):
    company_id: str
    user_email: str

@router.post("/admin")
async def admin_signup(request: AdminSignupRequest):
    # Log the request data for debugging
    print(f"Admin signup request: {request}")
    
    # Call Supabase RPC to create company + link admin
    result = supabase.rpc("admin_create_company_and_admin_user", {
        "company_name": request.company_name,
        "admin_email": request.admin_email,
    }).execute()
    
    print(f"Supabase RPC result: {result}")
    return {"message": "Admin company created successfully."}


@router.post("/user")
async def user_signup(request: UserSignupRequest):
    # Log the request data for debugging
    print(f"User signup request: {request}")
    
    # Call Supabase RPC to request joining company
    result = supabase.rpc("user_request_to_join_company", {
        "target_company_id": request.company_id,
        "user_email": request.user_email
    }).execute()
    
    print(f"Supabase RPC result: {result}")
    return {"message": "User signup request created successfully."}