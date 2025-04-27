from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from dependencies import supabase
from dependencies.auth import get_current_user

router = APIRouter()

class UserRequest(BaseModel):
    pending_user_email: str


@router.get("/pending-users")
async def get_pending_users(user = Depends(get_current_user)):
    """
    Get list of pending users for the admin's company (SECURE).
    """

    # Fetch the user record
    user_record = supabase.table("users").select("*").eq("email", user["email"]).single().execute()

    if not user_record.data:
        raise HTTPException(status_code=404, detail="User not found.")
    
    # Check if user is admin
    if user_record.data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can view pending users.")
    
    company_id = user_record.data["company_id"]
    
    # Now fetch pending users for the company
    pending_users = supabase.table("pending_users").select("*").eq("company_id", company_id).execute()
    
    return pending_users.data


@router.post("/approve-user")
async def approve_pending_user(request: UserRequest, user=Depends(get_current_user)):
    """
    Admin approves a pending user.
    """

    # Fetch the admin user record
    user_record = supabase.table("users").select("*").eq("email", user["email"]).single().execute()

    if not user_record.data:
        raise HTTPException(status_code=404, detail="Admin user not found.")
    
    if user_record.data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can approve users.")
    
    company_id = user_record.data["company_id"]

    # Fetch the pending user to approve
    pending_user = supabase.table("pending_users").select("*").eq("email", request.pending_user_email).single().execute()

    if not pending_user.data:
        raise HTTPException(status_code=404, detail="Pending user not found.")
    
    if pending_user.data["company_id"] != company_id:
        raise HTTPException(status_code=403, detail="You can only approve users from your company.")

    # Call Supabase RPC to approve user
    result = supabase.rpc("admin_approve_pending_user", {
        "pending_user_email": request.pending_user_email
    }).execute()

    if result.error:
        raise HTTPException(status_code=500, detail=f"Failed to approve user: {result.error}")

    return {"message": f"User {request.pending_user_email} approved successfully."}


@router.delete("/reject-user")
async def reject_pending_user(request: UserRequest, user=Depends(get_current_user)):
    """
    Admin rejects a pending user (removes from pending_users table).
    """

    # Fetch the admin user record
    user_record = supabase.table("users").select("*").eq("email", user["email"]).single().execute()

    if not user_record.data:
        raise HTTPException(status_code=404, detail="Admin user not found.")
    
    if user_record.data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can reject users.")
    
    company_id = user_record.data["company_id"]

    # Fetch the pending user to reject
    pending_user = supabase.table("pending_users").select("*").eq("email", request.pending_user_email).single().execute()

    if not pending_user.data:
        raise HTTPException(status_code=404, detail="Pending user not found.")
    
    if pending_user.data["company_id"] != company_id:
        raise HTTPException(status_code=403, detail="You can only reject users from your company.")

    # Delete the pending user
    delete_result = supabase.table("pending_users").delete().eq("email", request.pending_user_email).execute()

    if delete_result.error:
        raise HTTPException(status_code=500, detail=f"Failed to reject user: {delete_result.error}")

    return {"message": f"User {request.pending_user_email} rejected and removed successfully."}
