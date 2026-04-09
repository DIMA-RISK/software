import os
import time
import psycopg
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")
TABLE_NAME = os.getenv("TABLE_NAME")

if not TABLE_NAME:
    raise Exception("TABLE_NAME missing in .env")

def get_connection():
    return psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        sslmode=DB_SSLMODE,
    )

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
        conn.close()
        return

    row_id, job_id, org_uid = job
    print(f"Claimed job: row_id={row_id}, job_id={job_id}, org_uid={org_uid}")
    print("Status changed to running")

    time.sleep(2)

    mark_done(conn, row_id)
    print("Status changed to done ✅")

    conn.close()

if __name__ == "__main__":
    main()