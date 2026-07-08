from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "cyberplatform",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.risk_tasks",
        "app.tasks.vulnerability_tasks",
        "app.tasks.monitoring_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.risk_tasks.*": {"queue": "scoring"},
        "app.tasks.vulnerability_tasks.*": {"queue": "default"},
        "app.tasks.monitoring_tasks.*": {"queue": "monitoring"},
    },
    task_default_queue="default",
    worker_prefetch_multiplier=4,
    task_acks_late=True,
)

celery_app.conf.beat_schedule = {
    "refresh-sla-statuses-every-15-min": {
        "task": "app.tasks.vulnerability_tasks.refresh_all_sla_statuses",
        "schedule": crontab(minute="*/15"),
    },
    "recompute-org-risk-hourly": {
        "task": "app.tasks.risk_tasks.recompute_all_org_risk_scores",
        "schedule": crontab(minute=0),
    },
    "nvd-sync-every-2-hours": {
        "task": "app.tasks.vulnerability_tasks.sync_nvd_cves",
        "schedule": crontab(minute=0, hour="*/2"),
    },
    "daily-metrics-snapshot": {
        "task": "app.tasks.monitoring_tasks.daily_metrics_snapshot",
        "schedule": crontab(minute=0, hour=0),
    },
}
