
import random
from fastapi import APIRouter, Depends
from app.models.models import Fact
from app.models.schemas import FactSchema
from app.shared.security.secure_request import SecureRequest


router = APIRouter()


@router.get("/",
            response_model=FactSchema,
            dependencies=[Depends(SecureRequest({"fact"}))])
async def get_fact_request():
    fact_ids = await Fact.all().values_list("id", flat=True)
    random_id = random.choice(fact_ids)

    fact = await Fact.filter(id=random_id).prefetch_related('localizations').first()
    return fact
