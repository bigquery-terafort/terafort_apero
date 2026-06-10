#!/usr/bin/env python3
"""
================================================================================
 APERO PARTNER BUSINESS REPORT -> GCS -> BIGQUERY  (Phase 1: bearer-token mode)
================================================================================
 Flow:
   1. AUTH      : Bearer token from env (Phase 1) -- Phase 2 will swap in
                  refresh-token rotation via Secret Manager.
   2. PRODUCTS  : POST /product-metric/products  -> dynamic UUID list
                  (future-proof: new APLs are auto-included, never hardcoded).
   3. PULL      : POST /partner/business-report  -> last N days, PKT-pinned.
   4. VALIDATE  : schema check, date-window check, rollup-row checksum
                  reconciliation (explicit-fail on any mismatch).
   5. LAND      : raw JSON + NDJSON -> gs://<bucket>/raw/dt=YYYY-MM-DD/
   6. LOAD      : NDJSON -> BQ staging (truncate) -> MERGE into apero_daily
                  on (report_date, product_id)  => lookback restates cleanly,
                  never duplicates.

 Bleed-proof principles enforced:
   * Timezone pinned to +05:00 (PKT) explicitly -- running from a UTC Cloud
     Function/VM does NOT shift the window.
   * The 1970-01-01 ROLLUP grand-total row is used as a checksum, then
     dropped. It must never reach BigQuery.
   * No silent defaults: every unexpected condition raises and exits non-zero.

 Required env vars:
   APERO_BEARER_TOKEN   raw JWT (no "Bearer " prefix)
   GCS_BUCKET           e.g. terafort-apero
   BQ_PROJECT           your GCP project id
 Optional env vars:
   BQ_DATASET           default: apero
   BQ_TABLE             default: apero_daily
   LOOKBACK_DAYS        default: 30
   PRODUCTS_BODY_JSON   exact JSON body for the products endpoint
                        (default: '{"filterType":"partner-report"}' -- confirmed
                        from DevTools capture, matches content-length 31)
   DRY_RUN              "1" -> pull + validate + write local files only
   SKIP_GCS             "1" -> bypass the bucket, load BigQuery directly
                        (loses the raw replay/audit layer -- not recommended
                        for production, fine for ad-hoc pulls)
================================================================================
"""

import json
import os
import sys
import time
import datetime as dt
from zoneinfo import ZoneInfo

import requests

# ------------------------------------------------------------------ constants
BASE_URL = "https://mktpro.aperogroup.ai"
PRODUCTS_ENDPOINT = f"{BASE_URL}/api/v1/report/product-metric/products?filterType=partner-report"
REPORT_ENDPOINT = f"{BASE_URL}/api/v1/report/marketing-report/partner/business-report"

PKT = ZoneInfo("Asia/Karachi")          # +05:00 -- matches the browser payload
HTTP_TIMEOUT = 60                        # seconds
CHECKSUM_ABS_TOL = 0.05                  # USD tolerance for float-sum drift

REQUIRED_ROW_KEYS = {
    "first_open_time", "product_id", "app_name",
    "cutoff_revenue", "total_cost_USD", "total_tax_fee",
    "total_mkt_charge_fee", "total_service_package",
    "net_profit", "profit_per_revenue",
}
ADDITIVE_METRICS = [
    "cutoff_revenue", "total_cost_USD", "total_tax_fee",
    "total_mkt_charge_fee", "total_service_package", "net_profit",
]


def fail(msg: str) -> None:
    print(f"\n🚨 PIPELINE FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def env(name: str, default=None, required=False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        fail(f"Missing required env var: {name}")
    return val


# ------------------------------------------------------------------ 1. config
TOKEN = env("APERO_BEARER_TOKEN", required=True).strip()
if TOKEN.lower().startswith("bearer "):
    TOKEN = TOKEN[7:].strip()            # tolerate accidental prefix paste

LOOKBACK_DAYS = int(env("LOOKBACK_DAYS", "30"))
DRY_RUN = env("DRY_RUN", "0") == "1"
SKIP_GCS = env("SKIP_GCS", "0") == "1"          # 1 = load BQ directly, no raw landing zone
GCS_BUCKET = env("GCS_BUCKET", required=not (DRY_RUN or SKIP_GCS))
BQ_PROJECT = env("BQ_PROJECT", required=not DRY_RUN)
BQ_DATASET = env("BQ_DATASET", "apero")
BQ_TABLE = env("BQ_TABLE", "apero_daily")
PRODUCTS_BODY = env("PRODUCTS_BODY_JSON", '{"filterType":"partner-report"}')

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/partner-report/business",
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/148.0.0.0 Safari/537.36"),
}


def post_json(url: str, body: dict | str, step: str) -> dict:
    payload = body if isinstance(body, str) else json.dumps(body)
    # Retry transient failures (5xx / network) with backoff; never retry 4xx.
    attempts, delay = 4, 5
    resp = None
    for i in range(1, attempts + 1):
        try:
            resp = requests.post(url, data=payload, headers=HEADERS,
                                 timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            if i == attempts:
                fail(f"[{step}] network error after {attempts} attempts: {exc}")
            print(f"⚠️  [{step}] attempt {i}/{attempts} network error; "
                  f"retrying in {delay}s")
            time.sleep(delay)
            delay *= 2
            continue
        if resp.status_code >= 500:
            if i == attempts:
                fail(f"[{step}] HTTP {resp.status_code} after {attempts} "
                     f"attempts: {resp.text[:300]}")
            print(f"⚠️  [{step}] attempt {i}/{attempts} got HTTP "
                  f"{resp.status_code}; retrying in {delay}s")
            time.sleep(delay)
            delay *= 2
            continue
        break
    if resp.status_code == 401:
        fail(f"[{step}] 401 Unauthorized -- bearer token expired (1h lifetime). "
             f"Grab a fresh one from DevTools and re-run.")
    if resp.status_code != 200:
        fail(f"[{step}] HTTP {resp.status_code}: {resp.text[:500]}")
    try:
        return resp.json()
    except ValueError:
        fail(f"[{step}] response is not JSON: {resp.text[:500]}")


# --------------------------------------------------------- 2. product list
def fetch_products() -> list[dict]:
    data = post_json(PRODUCTS_ENDPOINT, PRODUCTS_BODY, "products")
    rows = data.get("dataSource")
    if not isinstance(rows, list) or not rows:
        fail("products endpoint returned no dataSource -- API shape may have "
             "changed; re-capture the request in DevTools and update "
             "PRODUCTS_BODY_JSON if needed.")
    products = []
    for r in rows:
        if not r.get("id") or not r.get("product_id"):
            fail(f"product row missing id/product_id: {r}")
        products.append({
            "uuid": r["id"],
            "product_id": r["product_id"],
            "app_name": r.get("app_name", ""),
            "bundle_ids": r.get("bundleId", []),
        })
    print(f"✅ products: {len(products)} -> "
          f"{', '.join(p['product_id'] for p in products)}")
    return products


# --------------------------------------------------------- 3. report pull
def window_pkt(lookback_days: int) -> tuple[str, str, dt.date, dt.date]:
    """Replicates the browser payload format exactly: YYYY-MM-DDT23:59:59+05:00"""
    today_pkt = dt.datetime.now(PKT).date()
    to_d = today_pkt - dt.timedelta(days=1)            # yesterday = last complete day
    from_d = to_d - dt.timedelta(days=lookback_days - 1)
    fmt = lambda d: f"{d.isoformat()}T23:59:59+05:00"
    return fmt(from_d), fmt(to_d), from_d, to_d


def fetch_report(product_uuids: list[str], from_iso: str, to_iso: str) -> dict:
    body = {
        "from_date": from_iso,
        "to_date": to_iso,
        "countries": [],
        "channels": [],
        "product_ids": product_uuids,
    }
    print(f"➡️  pulling {from_iso} -> {to_iso} for {len(product_uuids)} products")
    return post_json(REPORT_ENDPOINT, body, "business-report")


# --------------------------------------------------------- 4. validation
def is_rollup(row: dict) -> bool:
    return (str(row.get("first_open_time", "")).startswith("1970-01-01")
            or row.get("product_id", "") == "")


def validate_and_split(data: dict, from_d: dt.date, to_d: dt.date) -> tuple[list, dict]:
    rows = data.get("dataSource")
    if not isinstance(rows, list):
        fail("business-report response has no dataSource list")
    if len(rows) < 2:
        fail(f"suspiciously small response ({len(rows)} rows) -- refusing to load")

    detail, rollups = [], []
    for r in rows:
        missing = REQUIRED_ROW_KEYS - set(r.keys())
        if missing:
            fail(f"row missing keys {missing}: {r}")
        for m in ADDITIVE_METRICS:
            if not isinstance(r[m], (int, float)):
                fail(f"non-numeric metric {m}={r[m]!r} in row: {r}")
        (rollups if is_rollup(r) else detail).append(r)

    if len(rollups) != 1:
        fail(f"expected exactly 1 ROLLUP grand-total row, found {len(rollups)} -- "
             f"API behavior changed, refusing to load")
    rollup = rollups[0]

    # date-window sanity: every detail date must sit inside the requested window
    for r in detail:
        d = dt.date.fromisoformat(str(r["first_open_time"])[:10])
        if not (from_d <= d <= to_d):
            fail(f"row date {d} outside requested window {from_d}..{to_d} "
                 f"-- timezone bleed detected, aborting")

    # checksum: detail sums must equal the rollup row (free server-side audit)
    print("🔍 checksum vs ROLLUP grand-total row:")
    for m in ADDITIVE_METRICS:
        got = sum(r[m] for r in detail)
        exp = rollup[m]
        diff = abs(got - exp)
        status = "✅" if diff <= CHECKSUM_ABS_TOL else "🚨"
        print(f"   {status} {m:<24} detail={got:,.4f}  rollup={exp:,.4f}  diff={diff:.6f}")
        if diff > CHECKSUM_ABS_TOL:
            fail(f"checksum mismatch on {m}: detail-sum {got} != rollup {exp} "
                 f"(diff {diff}) -- partial/corrupt response, refusing to load")

    print(f"✅ validation passed: {len(detail)} detail rows, rollup row dropped")
    return detail, rollup


# --------------------------------------------------------- 5. land to GCS
def to_ndjson(detail: list, products: list, from_iso: str, to_iso: str,
              pulled_at: str) -> str:
    uuid_by_pid = {p["product_id"]: p["uuid"] for p in products}
    bundle_by_pid = {p["product_id"]: (p["bundle_ids"][0] if p["bundle_ids"] else None)
                     for p in products}
    lines = []
    for r in detail:
        lines.append(json.dumps({
            "report_date": str(r["first_open_time"])[:10],
            "product_id": r["product_id"],
            "product_uuid": uuid_by_pid.get(r["product_id"]),
            "app_name": r["app_name"],
            "package_name": bundle_by_pid.get(r["product_id"]),
            "revenue_usd": r["cutoff_revenue"],
            "cost_usd": r["total_cost_USD"],
            "tax_fee_usd": r["total_tax_fee"],
            "mkt_charge_fee_usd": r["total_mkt_charge_fee"],
            "service_package_usd": r["total_service_package"],
            "net_profit_usd": r["net_profit"],
            "profit_per_revenue": r["profit_per_revenue"],
            "window_from": from_iso,
            "window_to": to_iso,
            "pulled_at_utc": pulled_at,
        }))
    return "\n".join(lines) + "\n"


def land_and_load(raw: dict, ndjson: str, run_date: str) -> None:
    local_raw = f"/tmp/apero_raw_{run_date}.json"
    local_nd = f"/tmp/apero_{run_date}.ndjson"
    with open(local_raw, "w") as f:
        json.dump(raw, f)
    with open(local_nd, "w") as f:
        f.write(ndjson)
    print(f"💾 local: {local_raw} , {local_nd}")
    if DRY_RUN:
        print("🟡 DRY_RUN=1 -> skipping GCS upload and BigQuery load")
        return

    from google.cloud import bigquery

    # --- GCS raw landing zone (skippable with SKIP_GCS=1, but recommended)
    if not SKIP_GCS:
        from google.cloud import storage
        client = storage.Client(project=BQ_PROJECT)
        bucket = client.bucket(GCS_BUCKET)
        prefix = f"raw/dt={run_date}"
        for local, name in ((local_raw, "business_report_raw.json"),
                            (local_nd, "business_report.ndjson")):
            blob = bucket.blob(f"{prefix}/{name}")
            blob.upload_from_filename(local)
            print(f"☁️  gs://{GCS_BUCKET}/{prefix}/{name}")
    else:
        print("🟡 SKIP_GCS=1 -> no raw landing zone; loading BigQuery directly "
              "(no replay/audit copy will exist)")

    # --- BigQuery: truncate-load staging, then MERGE
    bq = bigquery.Client(project=BQ_PROJECT)
    stg = f"{BQ_PROJECT}.{BQ_DATASET}.{BQ_TABLE}_stg"
    tgt = f"{BQ_PROJECT}.{BQ_DATASET}.{BQ_TABLE}"

    schema = [
        bigquery.SchemaField("report_date", "DATE", mode="REQUIRED"),
        bigquery.SchemaField("product_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("product_uuid", "STRING"),
        bigquery.SchemaField("app_name", "STRING"),
        bigquery.SchemaField("package_name", "STRING"),
        bigquery.SchemaField("revenue_usd", "FLOAT64"),
        bigquery.SchemaField("cost_usd", "FLOAT64"),
        bigquery.SchemaField("tax_fee_usd", "FLOAT64"),
        bigquery.SchemaField("mkt_charge_fee_usd", "FLOAT64"),
        bigquery.SchemaField("service_package_usd", "FLOAT64"),
        bigquery.SchemaField("net_profit_usd", "FLOAT64"),
        bigquery.SchemaField("profit_per_revenue", "FLOAT64"),
        bigquery.SchemaField("window_from", "STRING"),
        bigquery.SchemaField("window_to", "STRING"),
        bigquery.SchemaField("pulled_at_utc", "TIMESTAMP"),
    ]
    job_cfg = bigquery.LoadJobConfig(
        schema=schema,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
    )
    if SKIP_GCS:
        with open(local_nd, "rb") as f:
            load = bq.load_table_from_file(f, stg, job_config=job_cfg)
    else:
        load = bq.load_table_from_uri(
            f"gs://{GCS_BUCKET}/{prefix}/business_report.ndjson",
            stg, job_config=job_cfg)
    load.result()
    print(f"📥 staging loaded: {stg} ({load.output_rows} rows)")

    # target table (partitioned, clustered) created once if absent
    bq.query(f"""
      CREATE TABLE IF NOT EXISTS `{tgt}` (
        report_date DATE NOT NULL,
        product_id STRING NOT NULL,
        product_uuid STRING, app_name STRING, package_name STRING,
        revenue_usd FLOAT64, cost_usd FLOAT64, tax_fee_usd FLOAT64,
        mkt_charge_fee_usd FLOAT64, service_package_usd FLOAT64,
        net_profit_usd FLOAT64, profit_per_revenue FLOAT64,
        window_from STRING, window_to STRING, pulled_at_utc TIMESTAMP
      )
      PARTITION BY report_date
      CLUSTER BY product_id
    """).result()

    merge = bq.query(f"""
      MERGE `{tgt}` T
      USING `{stg}` S
      ON T.report_date = S.report_date AND T.product_id = S.product_id
      WHEN MATCHED THEN UPDATE SET
        product_uuid=S.product_uuid, app_name=S.app_name,
        package_name=S.package_name, revenue_usd=S.revenue_usd,
        cost_usd=S.cost_usd, tax_fee_usd=S.tax_fee_usd,
        mkt_charge_fee_usd=S.mkt_charge_fee_usd,
        service_package_usd=S.service_package_usd,
        net_profit_usd=S.net_profit_usd,
        profit_per_revenue=S.profit_per_revenue,
        window_from=S.window_from, window_to=S.window_to,
        pulled_at_utc=S.pulled_at_utc
      WHEN NOT MATCHED THEN INSERT ROW
    """)
    merge.result()
    print(f"✅ MERGE complete into {tgt} "
          f"(rows affected: {merge.num_dml_affected_rows})")


# --------------------------------------------------------- main
def main() -> None:
    pulled_at = dt.datetime.now(dt.timezone.utc).isoformat()
    run_date = dt.datetime.now(PKT).date().isoformat()

    products = fetch_products()
    from_iso, to_iso, from_d, to_d = window_pkt(LOOKBACK_DAYS)
    raw = fetch_report([p["uuid"] for p in products], from_iso, to_iso)
    detail, _rollup = validate_and_split(raw, from_d, to_d)
    ndjson = to_ndjson(detail, products, from_iso, to_iso, pulled_at)
    land_and_load(raw, ndjson, run_date)
    print("\n🎯 DONE.")


if __name__ == "__main__":
    main()
