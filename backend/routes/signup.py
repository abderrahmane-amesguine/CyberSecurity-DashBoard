from fastapi import APIRouter, Body
from pydantic import BaseModel
from dependencies import supabase

router = APIRouter()

class AdminSignupRequest(BaseModel):
    company_name: str
    user_id: str

class UserSignupRequest(BaseModel):
    company_id: str
    user_id: str

@router.post("/admin")
def admin_signup(request: AdminSignupRequest):
    # Call Supabase RPC to create company + link admin
    supabase.rpc("admin_create_company_and_admin_user", {
        "company_name": request.company_name
    }).execute()

    return {"message": "Admin company created successfully."}


@router.post("/user")
def user_signup(request: UserSignupRequest):
    # Call Supabase RPC to request joining company
    supabase.rpc("user_request_to_join_company", {
        "target_company_id": request.company_id,
        "requester_id": request.user_id
    }).execute()

    return {"message": "User signup request created successfully."}