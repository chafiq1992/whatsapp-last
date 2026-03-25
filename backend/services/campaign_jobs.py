from datetime import datetime, timezone


def create_campaign_job(*, jobs: dict[str, dict], job_id: str, agent_username: str | None, store: str | None, workspace: str, template_name: str, language: str, limit: int, compiled_query: str) -> dict:
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": agent_username,
        "store": store,
        "workspace": workspace,
        "template_name": template_name,
        "language": language,
        "limit": limit,
        "compiled_query": compiled_query,
        "sent": 0,
        "failed": 0,
        "last_error": "",
    }
    jobs[job_id] = job
    return job


def get_campaign_job(jobs: dict[str, dict], job_id: str) -> dict | None:
    return jobs.get(str(job_id or "").strip())
