from fastapi import APIRouter, HTTPException
from db.database import connect
from sqlalchemy import text

router = APIRouter(prefix="/ioc")


def _safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)

@router.get("/{alert_id}")
def iocs(alert_id: str):

    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT ioc, ioc_type, source, score, verdict
                FROM ioc_enrichments
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()

        # Return plain JSON-serializable values.
        result = []
        for row in rows:
            if hasattr(row, "_mapping"):
                m = row._mapping
                result.append(
                    {
                        "ioc": _safe(m.get("ioc")),
                        "ioc_type": _safe(m.get("ioc_type")),
                        "source": _safe(m.get("source")),
                        "score": _safe(m.get("score")),
                        "verdict": _safe(m.get("verdict")),
                    }
                )
            elif isinstance(row, (list, tuple)):
                row_values = [_safe(value) for value in row]
                result.append(
                    {
                        "ioc": row_values[0] if len(row_values) > 0 else None,
                        "ioc_type": row_values[1] if len(row_values) > 1 else None,
                        "source": row_values[2] if len(row_values) > 2 else None,
                        "score": row_values[3] if len(row_values) > 3 else None,
                        "verdict": row_values[4] if len(row_values) > 4 else None,
                    }
                )
            else:
                result.append(
                    {
                        "ioc": str(row),
                        "ioc_type": None,
                        "source": None,
                        "score": None,
                        "verdict": None,
                    }
                )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to load IOC enrichment data") from exc
    finally:
        db.close()
