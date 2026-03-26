from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.db.init_db import init
from backend.routes import upload, analyze, incidents, timeline, chat, sessions

app = FastAPI(
    title="Cyber Analyst API",
    description="AI + ML cybersecurity analysis system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sessions.router, tags=["Sessions"])
app.include_router(upload.router, tags=["Upload"])
app.include_router(analyze.router, tags=["Analyze"])
app.include_router(incidents.router, tags=["Incidents"])
app.include_router(timeline.router, tags=["Timeline"])
app.include_router(chat.router, tags=["Chat"])


@app.on_event("startup")
def on_startup():
    init()


@app.get("/")
def root():
    return {"status": "running", "service": "Cyber Analyst API"}
