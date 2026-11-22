import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from .auth import current_user
from .db import files_dir

router = APIRouter()


@router.get("/templates")
def list_templates(user=Depends(current_user)):
    names = [n for n in os.listdir(files_dir()) if os.path.isfile(os.path.join(files_dir(), n))]
    return sorted(names)


@router.get("/templates/download")
def download_template(name: str, user=Depends(current_user)):
    path = os.path.join(files_dir(), name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Plantilla no encontrada")
    return FileResponse(path)
