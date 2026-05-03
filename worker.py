import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Optional
from pathlib import Path
import psycopg
from dotenv import load_dotenv

load_dotenv()

# DB connection: same style as your working test script
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

QUEUE_TABLE = os.getenv("QUEUE_TABLE")
RESULT_TABLE = os.getenv("RESULT_TABLE", "fact_software_results")

JOB_POLL_SECONDS = int(os.getenv("JOB_POLL_SECONDS", "2"))
JOB_TIMEOUT_SECONDS = int(os.getenv("JOB_TIMEOUT_SECONDS", "1800"))
WORKER_ID = os.getenv("WORKER_ID", socket.gethostname())

SOFTWARE_DIR = os.getenv("SOFTWARE_DIR", "./software")
SOFTWARE_SCRIPT = os.getenv(
    "SOFTWARE_SCRIPT",
    "ewnaf_v38.1_enterprise.sh",
)
BASE_OUTPUT_DIR = os.getenv("BASE_OUTPUT_DIR", "/tmp/ewnaf_jobs")

if not all([DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD]):
    raise RuntimeError("Missing one or more DB_* values in .env")

if not QUEUE_TABLE:
    raise RuntimeError("QUEUE_TABLE is missing in .env")

SCRIPT_PATH = os.path.join(SOFTWARE_DIR, SOFTWARE_SCRIPT)
STOP_WORKER = False


def handle_stop(signum, frame):
    global STOP_WORKER
    STOP_WORKER = True
    print(f"[INFO] Received signal {signum}. Stopping worker...")


signal.signal(signal.SIGINT, handle_stop)
signal.signal(signal.SIGTERM, handle_stop)


def get_connection():
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        sslmode=DB_SSLMODE,
    )


def ensure_base_output_dir() -> None:
    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)


def get_job_output_dir(job_id: int) -> str:
    return os.path.join(BASE_OUTPUT_DIR, f"job_{job_id}")


def prepare_job_output_dir(job_id: int) -> str:
    """
    Ensures a clean folder for this job.
    """
    job_dir = get_job_output_dir(job_id)

    if os.path.exists(job_dir):
        shutil.rmtree(job_dir)

    os.makedirs(job_dir, exist_ok=True)
    return job_dir


def claim_next_job(conn) -> Optional[Dict[str, Any]]:
    """
    Claim one queued job and mark it as running.
    Safe for future multi-worker usage.
    """
    sql = f"""
    WITH next_job AS (
        SELECT id
        FROM {QUEUE_TABLE}
        WHERE status = 'queued'
        ORDER BY created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE {QUEUE_TABLE} j
    SET status = 'running'
    FROM next_job
    WHERE j.id = next_job.id
    RETURNING j.id, j.job_id, j.org_uid, j.org_ip, j.created_at;
    """

    with conn.cursor() as cur:
        cur.execute(sql)
        row = cur.fetchone()

    conn.commit()

    if not row:
        return None

    return {
        "id": row[0],
        "job_id": row[1],
        "org_uid": row[2],
        "org_ip": row[3],
        "created_at": row[4],
    }


def update_status(conn, row_id: int, status: str) -> None:
    sql = f"""
    UPDATE {QUEUE_TABLE}
    SET status = %s
    WHERE id = %s
    """

    with conn.cursor() as cur:
        cur.execute(sql, (status, row_id))

    conn.commit()


def run_script(job: Dict[str, Any]) -> str:
    """
    Runs the shell script and forces all output files into:
    /tmp/ewnaf_jobs/job_<job_id>/

    Returns the job output directory.
    """
    if not os.path.isfile(SCRIPT_PATH):
        raise FileNotFoundError(f"Script not found: {SCRIPT_PATH}")

    job_id = job["job_id"]
    job_dir = prepare_job_output_dir(job_id)

    env = os.environ.copy()
    env["JOB_ROW_ID"] = str(job["id"])
    env["JOB_ID"] = "" if job["job_id"] is None else str(job["job_id"])
    env["ORG_UID"] = "" if job["org_uid"] is None else str(job["org_uid"])
    env["ORG_IP"] = "" if job["org_ip"] is None else str(job["org_ip"])
    env["WORKER_ID"] = WORKER_ID

    print(f"[INFO] Running script for job_id={job_id}")
    print(f"[INFO] Output dir: {job_dir}")

    result = subprocess.run(
        ["bash", SCRIPT_PATH, "-o", job_dir, "-q"],
        cwd=SOFTWARE_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=JOB_TIMEOUT_SECONDS,
        check=True,
    )

    if result.stdout:
        print(f"[INFO] stdout:\n{result.stdout[:2000]}")
    if result.stderr:
        print(f"[WARN] stderr:\n{result.stderr[:2000]}")

    return job_dir


def load_report_json(job_dir: str) -> Dict[str, Any]:
    job_path = Path(job_dir)

    matches = sorted(job_path.rglob("EWNAF-REPORT.json"))

    if not matches:
        raise FileNotFoundError(f"JSON report not found under: {job_dir}")

    json_path = matches[-1]  # latest one
    print(f"[INFO] Using JSON report: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def upsert_result(conn, job: Dict[str, Any], report_data: Dict[str, Any]) -> None:
    """
    Writes the JSON report into fact_software_results.
    Assumes one final result per job_id.
    """
    sql = f"""
    INSERT INTO {RESULT_TABLE} (org_uid, job_id, results)
    VALUES (%s, %s, %s::jsonb)
    ON CONFLICT (job_id)
    DO UPDATE SET
        org_uid = EXCLUDED.org_uid,
        results = EXCLUDED.results,
        created_at = NOW()
    """

    payload = json.dumps(report_data)

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (
                job["org_uid"],
                job["job_id"],
                payload,
            ),
        )

    conn.commit()


def process_job(conn, job: Dict[str, Any]) -> None:
    row_id = job["id"]
    job_id = job["job_id"]
    org_uid = job["org_uid"]

    print(f"[INFO] Processing row_id={row_id}, job_id={job_id}, org_uid={org_uid}")

    try:
        job_dir = run_script(job)
        report_data = load_report_json(job_dir)
        upsert_result(conn, job, report_data)

        update_status(conn, row_id, "done")
        print(f"[INFO] row_id={row_id} marked done")

    except subprocess.TimeoutExpired:
        print(f"[ERROR] row_id={row_id} timed out after {JOB_TIMEOUT_SECONDS} seconds")
        update_status(conn, row_id, "timed_out")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] row_id={row_id} failed with exit code {e.returncode}")

        if e.stdout:
            print(f"[ERROR] stdout:\n{e.stdout[:2000]}")
        if e.stderr:
            print(f"[ERROR] stderr:\n{e.stderr[:2000]}")

        update_status(conn, row_id, "failed")

    except Exception as e:
        print(f"[ERROR] row_id={row_id} failed: {e}")
        update_status(conn, row_id, "failed")


def main():
    print(f"[INFO] Worker started: {WORKER_ID}")
    print(f"[INFO] Queue table: {QUEUE_TABLE}")
    print(f"[INFO] Result table: {RESULT_TABLE}")
    print(f"[INFO] Script path: {SCRIPT_PATH}")
    print(f"[INFO] Base output dir: {BASE_OUTPUT_DIR}")
    print(f"[INFO] Poll every: {JOB_POLL_SECONDS}s")
    print(f"[INFO] Timeout: {JOB_TIMEOUT_SECONDS}s")

    ensure_base_output_dir()

    try:
        conn = get_connection()
        print("[INFO] Connected to DB")
    except Exception as e:
        print(f"[FATAL] Could not connect to DB: {e}")
        sys.exit(1)

    try:
        while not STOP_WORKER:
            try:
                job = claim_next_job(conn)

                if not job:
                    time.sleep(JOB_POLL_SECONDS)
                    continue

                process_job(conn, job)

            except psycopg.Error as e:
                print(f"[ERROR] Database error: {e}")
                try:
                    conn.rollback()
                except Exception:
                    pass
                time.sleep(5)

            except Exception as e:
                print(f"[ERROR] Worker loop error: {e}")
                try:
                    conn.rollback()
                except Exception:
                    pass
                time.sleep(5)

    finally:
        try:
            conn.close()
        except Exception:
            pass
        print("[INFO] Worker stopped")


if __name__ == "__main__":
    main()