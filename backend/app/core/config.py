import os
from pydantic import BaseModel
class Settings(BaseModel):
    backend_host: str=os.getenv("BACKEND_HOST","0.0.0.0")
    backend_port: int=int(os.getenv("BACKEND_PORT","8000"))
    cors_origin: str=os.getenv("CORS_ORIGIN","http://localhost:3000")
settings=Settings()
