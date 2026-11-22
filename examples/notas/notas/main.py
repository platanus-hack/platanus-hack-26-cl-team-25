from fastapi import FastAPI

from . import attachments, auth, notes, teams

app = FastAPI(title="Notas", version="0.3.0")

app.include_router(auth.router)
app.include_router(notes.router)
app.include_router(attachments.router)
app.include_router(teams.router)


@app.get("/health")
def health():
    return {"status": "ok"}
