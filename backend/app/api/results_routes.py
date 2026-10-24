from fastapi import APIRouter

from backend.app.services.results import load_results

router = APIRouter(tags=["results"])


@router.get("/results")
def get_results():
    """Evaluation results (configs C1 to C5). Falls back to flagged sample data."""
    return load_results()