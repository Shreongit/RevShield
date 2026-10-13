from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.analyze import router as analyze_router
from app.api.v1.extension import router as extension_router
from app.core.config import settings
from app.core.database import Base, engine
from app.ml.inference import get_or_load_model

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schemas on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Warm-up ML model
    get_or_load_model()
    yield

app = FastAPI(
    title="RevShield API",
    description="High-performance open-source website privacy, security, and threat analysis engine.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 Routers (Public Analysis & Extension Config)
app.include_router(analyze_router, prefix=settings.API_V1_STR)
app.include_router(extension_router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "RevShield Analysis Engine",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
