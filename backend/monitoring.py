import os
import logging
import time
from google.cloud import monitoring_v3
from google.protobuf.timestamp_pb2 import Timestamp

logger = logging.getLogger(__name__)

def record_scan_completion(project_id: str = None):
    """
    Increment the vaultscan/scan_jobs_total custom metric in Cloud Monitoring.
    """
    gcp_project = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not gcp_project:
        logger.warning("No GOOGLE_CLOUD_PROJECT set, skipping custom metric recording.")
        return

    try:
        client = monitoring_v3.MetricServiceClient()
        project_name = f"projects/{gcp_project}"

        series = monitoring_v3.TimeSeries()
        series.metric.type = "custom.googleapis.com/vaultscan/scan_jobs_total"
        
        point = monitoring_v3.Point()
        point.value.int64_value = 1
        
        now = time.time()
        timestamp = Timestamp()
        timestamp.FromSeconds(int(now))
        point.interval.end_time = timestamp

        series.points = [point]
        client.create_time_series(name=project_name, time_series=[series])
        logger.info("Successfully recorded scan_jobs_total metric.")
    except Exception as e:
        logger.error(f"Failed to record custom metric: {e}")
