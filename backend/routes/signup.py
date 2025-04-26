from fastapi import APIRouter
from dependencies import supabase

router = APIRouter()

@router.post("/admin")
def admin_signup(company_name: str):
    # Call Supabase RPC to create company + link admin
    supabase.rpc("admin_create_company_and_admin_user", {
        "company_name": company_name
    }).execute()

    return {"message": "Admin company created successfully."}


@router.post("/user")
def user_signup(company_id: str):
    # Call Supabase RPC to request joining company
    supabase.rpc("user_request_to_join_company", {
        "target_company_id": company_id
    }).execute()

    return {"message": "User signup request created successfully."}
