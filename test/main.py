"""
Main application entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from src.routes import parser_routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create FastAPI app
app = FastAPI(
    title="Universal Cybersecurity Log Parser",
    description="Parse any cybersecurity tool logs using Drain3",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(parser_routes.router)

@app.get("/")
async def root():
    return {
        "message": "Universal Cybersecurity Log Parser API",
        "version": "1.0.0",
        "endpoints": {
            "parse": "/api/parser/parse",
            "train": "/api/parser/train",
            "formats": "/api/parser/supported-formats",
            "realtime": "/api/parser/analyze-realtime"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)