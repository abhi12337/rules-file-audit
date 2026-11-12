# API package

- FastAPI app in `app/main.py`; run with `uvicorn app.main:app`.
- Settings come from environment variables via pydantic-settings.
- Never return stack traces to clients.
