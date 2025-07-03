# backend/api/predict_router.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from model.predict import predict_url  # Your model inference function

router = APIRouter()

class UrlRequest(BaseModel):
    url: str

@router.post("/predict")
def predict(request: UrlRequest):
    try:
        result = predict_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
