from fastapi import APIRouter, Depends

from core.indexer_client import IndexerClient
from core.security import current_user
from core.wazuh_client import WazuhClient

router = APIRouter(prefix="/integration")
client = WazuhClient()
indexer = IndexerClient()


@router.get("/status")
def status(user=Depends(current_user)):
    return {
        "wazuh_manager": client.status(),
        "indexer": indexer.status(),
    }
