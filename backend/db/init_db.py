"""Create all database tables."""

from backend.db.database import engine, Base
from backend.db.models import AnalysisSession, RawLog, Event, Incident, TimelineEvent, ChatMessage  # noqa: F401


def init():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")


if __name__ == "__main__":
    init()
