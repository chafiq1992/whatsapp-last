from fastapi import APIRouter, Body, Depends, Header, Request

router = APIRouter()


async def require_admin_dep(request: Request) -> dict:
    from ... import main as runtime

    agent = await runtime.get_current_agent(request)
    return await runtime.require_admin(agent)


@router.post("/customer-campaigns/launch")
async def launch_customer_campaign(body: dict = Body(...), agent: dict = Depends(require_admin_dep)):
    from ... import main as runtime

    return await runtime.launch_customer_campaign(body=body, agent=agent)


@router.get("/customer-campaigns/{job_id}")
async def get_customer_campaign(job_id: str, agent: dict = Depends(require_admin_dep)):
    from ... import main as runtime

    return await runtime.get_customer_campaign(job_id=job_id, agent=agent)


@router.post("/retargeting/customer-segments/launch")
async def launch_retargeting_customer_segments(
    body: dict = Body(...),
    agent: dict = Depends(require_admin_dep),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    from ... import main as runtime

    return await runtime.launch_retargeting_customer_segments(
        body=body,
        agent=agent,
        x_workspace=x_workspace,
    )


@router.post("/retargeting/customer-segments/preview")
async def preview_retargeting_customer_segments(
    body: dict = Body(...),
    agent: dict = Depends(require_admin_dep),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    from ... import main as runtime

    return await runtime.preview_retargeting_customer_segments(
        body=body,
        agent=agent,
        x_workspace=x_workspace,
    )


@router.get("/retargeting/jobs/{job_id}")
async def get_retargeting_job(job_id: str, agent: dict = Depends(require_admin_dep)):
    from ... import main as runtime

    return await runtime.get_retargeting_job(job_id=job_id, agent=agent)


@router.get("/retargeting/jobs")
async def list_retargeting_jobs(
    active_only: bool = True,
    limit: int = 200,
    agent: dict = Depends(require_admin_dep),
):
    from ... import main as runtime

    return await runtime.list_retargeting_jobs(active_only=active_only, limit=limit, agent=agent)


@router.post("/retargeting/jobs/{job_id}/stop")
async def stop_retargeting_job(job_id: str, agent: dict = Depends(require_admin_dep)):
    from ... import main as runtime

    return await runtime.stop_retargeting_job(job_id=job_id, agent=agent)
