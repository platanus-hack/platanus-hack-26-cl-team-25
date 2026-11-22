import uvicorn

from .app import create_app
from .config import Config

if __name__ == "__main__":
    cfg = Config.from_env()
    uvicorn.run(create_app(cfg), host="127.0.0.1", port=cfg.port, log_level="info", access_log=False)
