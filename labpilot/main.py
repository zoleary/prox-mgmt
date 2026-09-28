"""FastAPI app: dashboard API, chat, approval queue, and a background poller."""

import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, actions
from .analysis.memory import can_fit
from .chat import ChatService
from .config import get_settings
from .db import DB
from .integrations import build_integrations
from .state import LabState

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("labpilot")

settings = get_settings()
db = DB(settings.data_dir)
state = LabState(settings, build_integrations(settings))
chat = ChatService(settings, state, db)
security = HTTPBasic()


def require_user(creds: HTTPBasicCredentials = Depends(security)) -> str:
    ok = settings.admin_password and secrets.compare_digest(creds.username.encode(), settings.admin_user.encode()) \
        and secrets.compare_digest(creds.password.encode(), settings.admin_password.encode())
    if not ok:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return creds.username


def record_metrics() -> None:
    mem = {r["node"]: r for r in state.memory()["nodes"]}
    rows = [(state.updated, n["node"], n.get("cpu", 0), n.get("mem_used", 0), n.get("mem_total", 0),
             mem.get(n["node"], {}).get("assigned_running", 0)) for n in state.nodes if n.get("mem_total")]
    if rows:
        db.add_metrics(rows)


async def poller() -> None:
    while True:
        try:
            await asyncio.to_thread(state.refresh)
            await asyncio.to_thread(record_metrics)
        except Exception:
            log.exception("refresh failed")
        await asyncio.sleep(settings.poll_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.admin_password:
        raise RuntimeError("Set ADMIN_PASSWORD before starting LabPilot (it can change your lab).")
    task = asyncio.create_task(poller())
    yield
    task.cancel()


app = FastAPI(title="LabPilot", version=__version__, lifespan=lifespan)


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__}


api = FastAPI(dependencies=[Depends(require_user)])


@api.get("/overview")
def overview():
    return state.overview()


@api.get("/guests")
def guests():
    return state.guests


@api.get("/ipam")
def ipam():
    return state.ipam()


@api.get("/memory")
def memory():
    return state.memory()


@api.get("/memory/fit")
def memory_fit(gb: float):
    return can_fit(state.memory()["nodes"], int(gb * 1024**3), settings.mem_warn_ratio, settings.mem_crit_ratio)


@api.get("/metrics")
def metrics(hours: float = 24):
    return db.metrics(min(hours, 24 * 30))


@api.get("/raw/{integration}")
def raw(integration: str):
    return state.raw.get(integration, {})


@api.post("/refresh")
async def refresh():
    await asyncio.to_thread(state.refresh)
    await asyncio.to_thread(record_metrics)
    return {"updated": state.updated, "errors": state.errors}


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None


@api.post("/chat")
async def chat_send(body: ChatIn):
    if not settings.anthropic_api_key:
        raise HTTPException(400, "Set ANTHROPIC_API_KEY to use the assistant.")
    return await asyncio.to_thread(chat.send, body.session_id, body.message[:8000])


@api.post("/chat/{session_id}/reset")
def chat_reset(session_id: str):
    chat.reset(session_id)
    return {"ok": True}


@api.get("/actions")
def list_actions():
    return db.list_actions()


@api.post("/actions/{action_id}/approve")
async def approve(action_id: int):
    try:
        result = await asyncio.to_thread(actions.approve, state, db, action_id)
    except KeyError:
        raise HTTPException(404, "No such action")
    except ValueError as e:
        raise HTTPException(409, str(e))
    await asyncio.to_thread(state.refresh)
    return result


class DoIn(BaseModel):
    tool: str
    params: dict


@api.post("/do")
async def do(body: DoIn):
    """Run a change from a dashboard button. It is still logged in the change history."""
    if body.tool not in actions.DIRECT:
        raise HTTPException(400, f"{body.tool} can't be run directly")
    try:
        proposed = actions.propose(state, db, body.tool, body.params)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    result = await asyncio.to_thread(actions.approve, state, db, proposed["id"])
    await asyncio.to_thread(state.refresh)
    return result


@api.post("/actions/{action_id}/reject")
def reject(action_id: int):
    try:
        return actions.reject(db, action_id)
    except ValueError as e:
        raise HTTPException(409, str(e))


app.mount("/api", api)


@app.get("/", dependencies=[Depends(require_user)], include_in_schema=False)
def index():
    return FileResponse(Path(__file__).parent / "web" / "static" / "index.html")


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static")
