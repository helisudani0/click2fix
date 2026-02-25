from fastapi import APIRouter, Depends

from core.analytics import overview, kill_chain, alert_summary, hourly_volume
from core.security import current_user


router = APIRouter(prefix="/analytics")


@router.get("/overview")
def analytics_overview(user=Depends(current_user)):
    return overview()


@router.get("/kill-chain")
def analytics_kill_chain(case_id: int | None = None, user=Depends(current_user)):
    return kill_chain(case_id)


@router.get("/alert/{alert_id}")
def analytics_alert_summary(alert_id: str, user=Depends(current_user)):
    return alert_summary(alert_id)


@router.get("/hourly")
def analytics_hourly(hours: int = 72, user=Depends(current_user)):
    hours = max(1, min(hours, 720))
    return {"hours": hours, "series": hourly_volume(hours)}
