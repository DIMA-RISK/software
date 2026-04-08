import os
import time
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
TABLE_NAME = os.getenv("TABLE_NAME", "JOB_QUEUE_TABLE")

if not DATABASE_URL:
    raise Exception("DATABASE_URL missing")

def get_connection():
    return psycopg.connect(DATABASE_URL)

def claim_job(conn):
    sql = f"""
    WITH next_job AS (
        SELECT id
        FROM {TABLE_NAME}
        WHERE status = 'queued'
        ORDER BY created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE {TABLE_NAME} j
    SET status = 'running'
    FROM next_job
    WHERE j.id = next_job.id
    RETURNING j.id, j.job_id, j.org_uid;
    """

    with conn.cursor() as cur:
        cur.execute(sql)
        row = cur.fetchone()
    conn.commit()

    return row

def mark_done(conn, row_id):
    sql = f"""
    UPDATE {TABLE_NAME}
    SET status = 'done'
    WHERE id = %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (row_id,))
    conn.commit()

def main():
    print("Connecting to DB...")

    conn = get_connection()
    print("Connected ✅")

    job = claim_job(conn)

    if not job:
        print("No queued jobs found")
        return

    row_id, job_id, org_uid = job

    print(f"Claimed job: row_id={row_id}, job_id={job_id}, org_uid={org_uid}")

    print("Simulating work...")
    time.sleep(2)

    mark_done(conn, row_id)

    print(f"Job {row_id} marked as DONE ✅")

    conn.close()

if __name__ == "__main__":
    main()