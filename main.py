from fastapi import FastAPI

app = FastAPI(title="Cloudhunter API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/v1/findings")
def list_findings():
    # TODO: read from PostgreSQL
    return {"findings": []}
