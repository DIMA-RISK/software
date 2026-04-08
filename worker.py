import os
import time
import signal
import socket
import subprocess
from typing import Optional, Dict, Any

import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JOB_POLL_SECONDS = int(os.getenv("JOB_POLL_SECONDS", "2"))
JOB_TIMEOUT_SECONDS = int(os.getenv("JOB_TIMEOUT_SECONDS", "600"))
SOFTWARE_DIR = os.getenv("SOFTWARE_DIR", "./software")
SOFTWARE_SCRIPT = os.getenv("SOFTWARE_SCRIPT", "ewnaf_v36_6_polished_gold_best_effort.sh")
TABLE_NAME = os.getenv("TABLE_NAME", "job_queue")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing in .env")

SCRIPT_PATH = os.path.join(SOFTWARE_DIR, SOFTWARE_SCRIPT)
STOP_WORKER = False


def handle_stop(signum, frame):
    global STOP_WORKER
    STOP_WORKER = True
    print(f"[INFO] Received signal {signum}. Stopping worker...")


signal.signal(signal.SIGINT, handle_stop)
signal.signal(signal.SIGTERM, handle_stop)


def get_connection():
    return psycopg.connect(DATABASE_URL)


def claim_next_job(conn) -> Optional[Dict[str, Any]]:
    """
    Safely claim one queued job.
    FOR UPDATE SKIP LOCKED lets multiple workers run later without claiming the same row.
    """
    sql = f"""
    WITH next_job AS (
        SELECT id
        FROM {TABLE_name}
        WHERE status = 'queued'
        ORDER BY created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    UPDATE {TABLE_name} j
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


def mark_status(conn, row_id: int, status: str) -> None:
    sql = f"""
    UPDATE {TABLE_NAME}
    SET status = %s
    WHERE id = %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (status, row_id))
    conn.commit()


def run_script(job: Dict[str, Any]) -> subprocess.CompletedProcess:
    """
    Runs your shell script.
    Since the script auto-detects what it needs, we do not pass org_ip.
    But we do expose job context as environment variables in case you want them later.
    """
    if not os.path.isfile(SCRIPT_PATH):
        raise FileNotFoundError(f"Script not found: {SCRIPT_PATH}")

    env = os.environ.copy()
    env["JOB_ROW_ID"] = str(job["id"])
    env["JOB_ID"] = "" if job["job_id"] is None else str(job["job_id"])
    env["ORG_UID"] = "" if job["org_uid"] is None else str(job["org_uid"])
    env["ORG_IP"] = "" if job["org_ip"] is None else str(job["org_ip"])

    result = subprocess.run(
        ["bash", SCRIPT_PATH],
        cwd=SOFTWARE_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=JOB_TIMEOUT_SECONDS,
        check=True,
    )
    return result


def process_job(conn, job: Dict[str, Any]) -> None:
    row_id = job["id"]
    job_id = job["job_id"]
    org_uid = job["org_uid"]

    print(f"[INFO] Processing row_id={row_id}, job_id={job_id}, org_uid={org_uid}")

    try:
        result = run_script(job)

        if result.stdout:
            print(f"[INFO] stdout:\n{result.stdout[:1000]}")
        if result.stderr:
            print(f"[WARN] stderr:\n{result.stderr[:1000]}")

        mark_status(conn, row_id, "done")
        print(f"[INFO] row_id={row_id} marked done")

    except subprocess.TimeoutExpired:
        print(f"[ERROR] row_id={row_id} timed out after {JOB_TIMEOUT_SECONDS}s")
        mark_status(conn, row_id, "timed_out")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] row_id={row_id} failed with exit code {e.returncode}")
        if e.stdout:
            print(f"[ERROR] stdout:\n{e.stdout[:1000]}")
        if e.stderr:
            print(f"[ERROR] stderr:\n{e.stderr[:1000]}")
        mark_status(conn, row_id, "failed")

    except Exception as e:
        print(f"[ERROR] row_id={row_id} failed: {e}")
        mark_status(conn, row_id, "failed")


def main():
    print(f"[INFO] Watching table: {TABLE_NAME}")
    print(f"[INFO] Script path: {SCRIPT_PATH}")

    conn = get_connection()

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
        conn.close()
        print("[INFO] Worker stopped")


if __name__ == "__main__":
    main()