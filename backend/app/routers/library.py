from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from ..database import get_db
from .. import scripts_library as lib
from .auth import get_current_user

router = APIRouter(prefix="/library", tags=["library"])


@router.get("/nmap/options")
async def nmap_options(category: str | None = None, user: str = Depends(get_current_user)):
    items = lib.NMAP_OPTIONS
    if category and category != "all":
        items = [o for o in items if o["category"] == category]
    return {"count": len(items), "items": items}


@router.get("/nmap/option-categories")
async def nmap_option_categories(user: str = Depends(get_current_user)):
    cats = sorted({o["category"] for o in lib.NMAP_OPTIONS})
    return cats


@router.get("/nmap/scripts")
async def nmap_scripts(
    category: str | None = None,
    search: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    user: str = Depends(get_current_user),
):
    items = lib.list_nmap_scripts(category=category, search=search, limit=limit)
    return {"count": len(items), "items": items, "categories": lib.NSE_CATEGORIES}


@router.get("/nse/categories")
async def nse_categories(user: str = Depends(get_current_user)):
    return lib.NSE_CATEGORIES


@router.get("/kali")
async def kali_tools(
    category: str | None = None,
    search: str | None = None,
    phase: int | None = None,
    user: str = Depends(get_current_user),
):
    items = lib.list_kali_tools(category=category, search=search, phase=phase)
    return {"count": len(items), "items": items}


@router.get("/kali/categories")
async def kali_categories(user: str = Depends(get_current_user)):
    return lib.KALI_CATEGORIES


@router.get("/presets")
async def presets(
    phase: int | None = None,
    tool: str | None = None,
    user: str = Depends(get_current_user),
):
    items = lib.PRESET_TEMPLATES
    if phase is not None:
        items = [p for p in items if p["phase"] == phase]
    if tool:
        items = [p for p in items if p["tool"] == tool]
    return {"count": len(items), "items": items}


@router.get("/search")
async def global_search(
    q: str = Query(..., min_length=2),
    user: str = Depends(get_current_user),
):
    """One-shot cross-search: nmap options, NSE scripts, Kali tools, presets."""
    q_lower = q.lower()
    nmap_opts = [o for o in lib.NMAP_OPTIONS if q_lower in o["flag"].lower() or q_lower in o["name"].lower() or q_lower in o["desc"].lower()]
    nse = lib.list_nmap_scripts(search=q, limit=40)
    kali = lib.list_kali_tools(search=q)
    presets = [p for p in lib.PRESET_TEMPLATES if q_lower in p["label"].lower() or q_lower in p["tool"].lower() or q_lower in p.get("template", "").lower()]
    return {
        "q": q,
        "nmap_options": nmap_opts,
        "nse_scripts": nse,
        "kali_tools": kali,
        "presets": presets,
    }
