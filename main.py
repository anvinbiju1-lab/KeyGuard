import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from entropy import analyze_entropy
from breach import check_breach

app = FastAPI(
    title="KeyGuard API",
    description="Zero-Knowledge Password Strength and Breach Auditor API",
    version="1.0.0"
)

# Enable CORS for local development and enterprise deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    password: str = Field(..., description="Password to analyze", example="Correct-Horse-Battery-Staple-2026!")

@app.post("/api/analyze")
async def analyze_password(payload: AnalyzeRequest):
    """
    Accepts password payload, calculates mathematical entropy, evaluates pool composition,
    and performs a Zero-Knowledge k-Anonymity audit against the HaveIBeenPwned database.
    """
    password = payload.password
    
    # 1. Calculate entropy and password composition metrics
    entropy_data = analyze_entropy(password)

    # 2. Perform Zero-Knowledge breach check using HIBP k-Anonymity
    breach_data = await check_breach(password)

    # Combine analysis into a unified enterprise response
    response_data = {
        "password_length": entropy_data["length"],
        "entropy": entropy_data["entropy"],
        "pool_size": entropy_data["pool_size"],
        "strength": entropy_data["strength"],
        "crack_time_display": entropy_data["crack_time_display"],
        "is_breached": breach_data["is_breached"],
        "breach_count": breach_data["breach_count"],
        "sha1_prefix": breach_data["sha1_prefix"],
        "sha1_suffix_masked": breach_data["sha1_suffix_masked"],
        "breach_check_status": breach_data["status"],
        "pool_breakdown": entropy_data["pool_breakdown"],
        "recommendations": entropy_data["recommendations"]
    }

    return response_data

# Mount static files directory if present
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def read_index():
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "KeyGuard API active. Static frontend file index.html not found."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
