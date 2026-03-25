import json
from datetime import datetime, timezone

from ..core.runtime_types import RetargetingRuntime


async def ensure_retargeting_jobs_table(runtime: RetargetingRuntime) -> None:
    try:
        async with runtime.db_manager._conn() as db:  # type: ignore[attr-defined]
            stmt = runtime.db_manager._convert(
                """
                CREATE TABLE IF NOT EXISTS retargeting_jobs (
                    id          TEXT PRIMARY KEY,
                    workspace   TEXT,
                    status      TEXT,
                    data        TEXT,
                    created_at  TEXT,
                    updated_at  TEXT
                )
                """
            )
            await db.execute(stmt)
            if not getattr(runtime.db_manager, "use_postgres", False):
                await db.commit()
    except Exception:
        return


async def rt_job_upsert(runtime: RetargetingRuntime, job: dict) -> None:
    try:
        await ensure_retargeting_jobs_table(runtime)
    except Exception:
        pass
    try:
        jid = str(job.get("id") or "").strip()
        if not jid:
            return
        ws = str(job.get("workspace") or "").strip().lower() or None
        st = str(job.get("status") or "").strip()
        created_at = str(job.get("created_at") or "") or datetime.now(timezone.utc).isoformat()
        updated_at = datetime.now(timezone.utc).isoformat()
        data = json.dumps(job, ensure_ascii=False)
        async with runtime.db_manager._conn() as db:  # type: ignore[attr-defined]
            if getattr(runtime.db_manager, "use_postgres", False):
                await db.execute(
                    runtime.db_manager._convert(
                        """
                        INSERT INTO retargeting_jobs (id, workspace, status, data, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT(id) DO UPDATE SET
                          workspace = EXCLUDED.workspace,
                          status = EXCLUDED.status,
                          data = EXCLUDED.data,
                          updated_at = EXCLUDED.updated_at
                        """
                    ),
                    jid,
                    ws,
                    st,
                    data,
                    created_at,
                    updated_at,
                )
            else:
                await db.execute(
                    runtime.db_manager._convert(
                        """
                        INSERT INTO retargeting_jobs (id, workspace, status, data, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                          workspace = excluded.workspace,
                          status = excluded.status,
                          data = excluded.data,
                          updated_at = excluded.updated_at
                        """
                    ),
                    (jid, ws, st, data, created_at, updated_at),
                )
                await db.commit()
    except Exception:
        return


async def rt_job_get(runtime: RetargetingRuntime, job_id: str) -> dict | None:
    jid = str(job_id or "").strip()
    if not jid:
        return None
    j = runtime.jobs.get(jid)
    if isinstance(j, dict):
        return j
    try:
        await ensure_retargeting_jobs_table(runtime)
        async with runtime.db_manager._conn() as db:  # type: ignore[attr-defined]
            q = runtime.db_manager._convert("SELECT data FROM retargeting_jobs WHERE id = ?")
            if getattr(runtime.db_manager, "use_postgres", False):
                q = runtime.db_manager._convert("SELECT data FROM retargeting_jobs WHERE id = $1")
                row = await db.fetchrow(q, jid)
                raw = row[0] if row else None
            else:
                cur = await db.execute(q, (jid,))
                row = await cur.fetchone()
                raw = row["data"] if row else None
        if raw:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None
    return None


async def rt_job_list(
    runtime: RetargetingRuntime,
    *,
    active_only: bool,
    limit: int,
    workspace: str | None = None,
) -> list[dict]:
    lim = max(1, min(int(limit or 200), 1000))
    active_statuses = {"queued", "waiting", "running", "sleeping", "stopping"}
    ws = str(workspace or "").strip().lower() or None
    out: list[dict] = []
    try:
        await ensure_retargeting_jobs_table(runtime)
        async with runtime.db_manager._conn() as db:  # type: ignore[attr-defined]
            if getattr(runtime.db_manager, "use_postgres", False):
                if ws:
                    rows = await db.fetch(
                        runtime.db_manager._convert(
                            "SELECT data FROM retargeting_jobs WHERE workspace = $1 ORDER BY created_at DESC LIMIT $2"
                        ),
                        ws,
                        lim,
                    )
                else:
                    rows = await db.fetch(
                        runtime.db_manager._convert(
                            "SELECT data FROM retargeting_jobs ORDER BY created_at DESC LIMIT $1"
                        ),
                        lim,
                    )
                for row in rows or []:
                    try:
                        obj = json.loads(row[0]) if row and row[0] else None
                        if isinstance(obj, dict):
                            out.append(obj)
                    except Exception:
                        continue
            else:
                if ws:
                    cur = await db.execute(
                        runtime.db_manager._convert(
                            "SELECT data FROM retargeting_jobs WHERE workspace = ? ORDER BY created_at DESC LIMIT ?"
                        ),
                        (ws, lim),
                    )
                else:
                    cur = await db.execute(
                        runtime.db_manager._convert(
                            "SELECT data FROM retargeting_jobs ORDER BY created_at DESC LIMIT ?"
                        ),
                        (lim,),
                    )
                rows = await cur.fetchall()
                for row in rows or []:
                    try:
                        raw = row["data"]
                        obj = json.loads(raw) if raw else None
                        if isinstance(obj, dict):
                            out.append(obj)
                    except Exception:
                        continue
    except Exception:
        out = []

    if active_only:
        out = [j for j in out if str(j.get("status") or "") in active_statuses]
    try:
        out.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
    except Exception:
        pass
    return out[:lim]


async def rt_should_stop(runtime: RetargetingRuntime, job_id: str) -> bool:
    try:
        if runtime.jobs.get(job_id, {}).get("stop_requested"):
            return True
    except Exception:
        pass
    try:
        job = await rt_job_get(runtime, job_id)
        return bool((job or {}).get("stop_requested"))
    except Exception:
        return False
