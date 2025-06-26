from dependencies.auth import get_current_user
from dependencies.supabase import supabase
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/me")
async def get_me(user=Depends(get_current_user)):
    """
    Get the current user's information including role (SECURE).
    """
    try:
        # First get the user's company role
        request_user = supabase.table("users").select("*").eq("user_id", user["id"]).single().execute()
        
        if not company_user.data:
            raise HTTPException(status_code=404, detail="User profile not found")


        user_data = {
            **user,
            **request_user.data
        }

        return JSONResponse(content=user_data)
    except Exception as e:
        print(f"Error in /me endpoint: {str(e)}")  # Debug log
        raise HTTPException(status_code=500, detail=str(e))