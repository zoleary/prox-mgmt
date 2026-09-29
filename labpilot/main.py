"""FastAPI app: dashboard API, chat, approval queue, and a background poller."""

import asyncio
import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, actions, inventory
from .discovery import Discovery
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
state = LabState(settings, build_integrations(settings), db)
chat = ChatService(settings, state, db)
security = HTTPBasic()
discovery = Discovery()


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
        raise RuntimeError("Set ADMIN_PASSWORD before starting Lab Helper (it can change your lab).")
    task = asyncio.create_task(poller())
    yield
    task.cancel()


app = FastAPI(title="Lab Helper", version=__version__, lifespan=lifespan)


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


@api.get("/alerts")
def alerts():
    return state.alerts


class AlertKey(BaseModel):
    key: str
    message: str = ""


@api.post("/alerts/ignore")
def ignore_alert(body: AlertKey):
    db.ignore_alert(body.key[:200], body.message[:500])
    state.update_alerts()
    return {"alerts": state.alerts, "ignored": state.ignored_alerts}


@api.post("/alerts/unignore")
def unignore_alert(body: AlertKey):
    db.unignore_alert(body.key)
    state.update_alerts()
    return {"alerts": state.alerts, "ignored": state.ignored_alerts}


@api.get("/devices")
def devices():
    return {"devices": state.devices_with_status(), "kinds": inventory.KINDS}


def _save_device(body: dict, device_id: int | None):
    try:
        clean = inventory.clean_device(body)
        new_id = db.save_device(clean, device_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(404, "No such device")
    state.load_devices()
    return db.get_device(new_id)


@api.post("/devices")
def add_device(body: dict):
    return _save_device(body, None)


@api.put("/devices/{device_id}")
def update_device(device_id: int, body: dict):
    return _save_device(body, device_id)


@api.delete("/devices/{device_id}")
def delete_device(device_id: int):
    if not db.delete_device(device_id):
        raise HTTPException(404, "No such device")
    state.load_devices()
    state.device_status.pop(device_id, None)
    return {"ok": True}


@api.get("/topology")
def topology():
    return state.topology()


@api.get("/discovery")
def discovery_status():
    suggested = [s["cidr"] for s in state.ipam()["subnets"]]
    return {**discovery.status(), "suggested_subnets": suggested}


class DiscoverIn(BaseModel):
    subnets: list[str]


@api.post("/discovery")
def discovery_start(body: DiscoverIn):
    try:
        return discovery.start(body.subnets, state.ipam()["addresses"], state.devices)
    except ValueError as e:
        raise HTTPException(400, str(e))


class BulkDevicesIn(BaseModel):
    devices: list[dict]


@api.post("/devices/bulk")
def add_devices(body: BulkDevicesIn):
    """Add discovered devices. Skips any whose IP is already in the inventory."""
    have = {d["ip"] for d in db.list_devices() if d.get("ip")}
    added, skipped, errors = [], [], []
    for raw in body.devices[:500]:
        try:
            clean = inventory.clean_device(raw)
        except ValueError as e:
            errors.append(f"{raw.get('name') or raw.get('ip')}: {e}")
            continue
        if clean["ip"] and clean["ip"] in have:
            skipped.append(clean["name"])
            continue
        db.save_device(clean)
        have.add(clean["ip"])
        added.append(clean["name"])
    state.load_devices()
    return {"added": added, "skipped": skipped, "errors": errors}


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


STATIC = Path(__file__).parent / "web" / "static"
# Stamp the script and stylesheet URLs with a content hash so browsers load the new files after an update.
ASSET_VERSION = hashlib.sha256(b"".join((STATIC / f).read_bytes() for f in ("app.js", "style.css"))).hexdigest()[:12]
INDEX_HTML = ((STATIC / "index.html").read_text()
              .replace('/static/app.js"', f'/static/app.js?v={ASSET_VERSION}"')
              .replace('/static/style.css"', f'/static/style.css?v={ASSET_VERSION}"'))


@app.get("/", dependencies=[Depends(require_user)], include_in_schema=False)
def index():
    return HTMLResponse(INDEX_HTML, headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
