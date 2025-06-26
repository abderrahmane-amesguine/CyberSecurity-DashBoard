from fastapi import FastAPI, Request
from routes import signup, admin, login
from fastapi.middleware.cors import CORSMiddleware
from middleware.debug_middleware import logging_middleware

app = FastAPI()

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "https://*.app.github.dev", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include our debug middleware
@app.middleware("http")
async def debug_request(request: Request, call_next):
    return await logging_middleware(request, call_next)

# Include the signup router
app.include_router(signup.router, prefix="/api/signup")

# Include the admin router
app.include_router(admin.router, prefix="/api/admin")

# Include the login router
app.include_router(login.router, prefix="/api/login")

# Add a test route to verify the API is working
@app.get("/api/test")
async def test_api():
    return {"message": "API is working correctly"}