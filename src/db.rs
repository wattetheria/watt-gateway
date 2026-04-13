use crate::models::{
    GatewayRegistryDbRow, GatewayRegistryEntry, NodeSourceRow, ProjectionRow,
    SignedGatewayManifest, SnapshotRow, UiEventRow,
};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct UpsertSnapshotRecord<'a> {
    pub source_id: Option<Uuid>,
    pub node_id: &'a str,
    pub signer_agent_did: &'a str,
    pub public_key: &'a str,
    pub generated_at: i64,
    pub payload: &'a Value,
    pub signature: &'a str,
}

pub struct UpsertGatewayManifestRecord<'a> {
    pub manifest: &'a SignedGatewayManifest,
}

pub struct InsertNodeSourceRecord<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub export_url: &'a str,
    pub wattetheria_snapshot_export_url: Option<&'a str>,
    pub wattetheria_events_export_url: Option<&'a str>,
    pub wattswarm_ui_base_url: Option<&'a str>,
    pub wattswarm_sync_grpc_endpoint: Option<&'a str>,
    pub region: Option<&'a str>,
    pub expected_signer_agent_did: Option<&'a str>,
    pub expected_wattswarm_node_id: Option<&'a str>,
    pub source_status: &'a str,
    pub transport_capabilities: Option<&'a Value>,
    pub transport_contact_material: Option<&'a Value>,
}

pub struct UpsertProjectionRecord<'a> {
    pub data_kind: &'a str,
    pub identity_key: &'a str,
    pub source_node_id: &'a str,
    pub source_id: Option<Uuid>,
    pub generated_at: i64,
    pub visibility: &'a str,
    pub payload: &'a Value,
    pub provenance: &'a Value,
}

pub struct InsertUiEventRecord<'a> {
    pub event_id: &'a str,
    pub source_id: Option<Uuid>,
    pub node_id: &'a str,
    pub signer_agent_did: &'a str,
    pub data_kind: &'a str,
    pub event_kind: &'a str,
    pub visibility: &'a str,
    pub provisional: bool,
    pub topic_id: Option<&'a str>,
    pub organization_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub generated_at: i64,
    pub payload: &'a Value,
    pub ingest_path: &'a str,
    pub source_cursor_or_seq: Option<i64>,
}

pub struct ListUiEventsQuery<'a> {
    pub cursor: i64,
    pub data_kind: Option<&'a str>,
    pub node_id: Option<&'a str>,
    pub topic_id: Option<&'a str>,
    pub organization_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub limit: i64,
}

pub struct InsertAuditRecord<'a> {
    pub record_kind: &'a str,
    pub data_kind: Option<&'a str>,
    pub identity_key: Option<&'a str>,
    pub source_id: Option<Uuid>,
    pub source_node_id: Option<&'a str>,
    pub generated_at: Option<i64>,
    pub ingest_path: &'a str,
    pub payload: &'a Value,
    pub provenance: &'a Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayHealthCounts {
    pub source_count: i64,
    pub active_source_count: i64,
    pub snapshot_count: i64,
    pub projection_count: i64,
    pub ui_event_count: i64,
    pub backfill_event_count: i64,
}

pub async fn max_ui_event_source_seq(
    pool: &PgPool,
    node_id: &str,
    source_id: Option<Uuid>,
) -> Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        select max(source_cursor_or_seq) as max_seq
        from gateway_ui_events
        where node_id = $1
          and (
            ($2::uuid is null and source_id is null)
            or source_id = $2
          )
        "#,
    )
    .bind(node_id)
    .bind(source_id)
    .fetch_one(pool)
    .await?;
    Ok(row.try_get("max_seq")?)
}

pub async fn connect(database_url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?)
}

pub async fn init_schema(pool: &PgPool) -> Result<()> {
    sqlx::query(
        r#"
        create table if not exists node_sources (
            id uuid primary key,
            name text not null,
            export_url text not null unique,
            wattetheria_snapshot_export_url text null,
            wattetheria_events_export_url text null,
            wattswarm_ui_base_url text null,
            wattswarm_sync_grpc_endpoint text null,
            region text null,
            expected_signer_agent_did text null,
            expected_wattswarm_node_id text null,
            source_status text not null default 'active',
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now(),
            last_sync_at timestamptz null,
            last_sync_status text null,
            last_error text null,
            transport_capabilities jsonb null,
            transport_contact_material jsonb null
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists wattetheria_snapshot_export_url text null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists wattetheria_events_export_url text null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists wattswarm_ui_base_url text null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists wattswarm_sync_grpc_endpoint text null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists expected_wattswarm_node_id text null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists source_status text not null default 'active';
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        update node_sources
        set wattetheria_snapshot_export_url = coalesce(wattetheria_snapshot_export_url, export_url)
        where wattetheria_snapshot_export_url is null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists transport_capabilities jsonb null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        alter table node_sources
            add column if not exists transport_contact_material jsonb null;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create table if not exists gateway_projection_rows (
            data_kind text not null,
            identity_key text not null,
            source_node_id text not null,
            source_id uuid null references node_sources(id) on delete set null,
            generated_at bigint not null,
            ingested_at timestamptz not null default now(),
            visibility text not null,
            payload jsonb not null,
            provenance jsonb not null,
            primary key (data_kind, identity_key, source_node_id)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_projection_rows_kind_generated
        on gateway_projection_rows(data_kind, generated_at desc);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create table if not exists gateway_ui_events (
            cursor bigserial primary key,
            event_id text not null unique,
            source_id uuid null references node_sources(id) on delete set null,
            node_id text not null,
            signer_agent_did text not null,
            data_kind text not null,
            event_kind text not null,
            visibility text not null,
            provisional boolean not null default false,
            topic_id text null,
            organization_id text null,
            task_id text null,
            generated_at bigint not null,
            ingested_at timestamptz not null default now(),
            payload jsonb not null,
            ingest_path text not null,
            source_cursor_or_seq bigint null
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_ui_events_cursor on gateway_ui_events(cursor);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_ui_events_kind_cursor
        on gateway_ui_events(data_kind, cursor desc);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create table if not exists gateway_ingest_audit (
            id bigserial primary key,
            record_kind text not null,
            data_kind text null,
            identity_key text null,
            source_id uuid null references node_sources(id) on delete set null,
            source_node_id text null,
            generated_at bigint null,
            ingest_path text not null,
            payload jsonb not null,
            provenance jsonb not null,
            created_at timestamptz not null default now()
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_ingest_audit_kind_created
        on gateway_ingest_audit(record_kind, created_at desc);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create table if not exists node_snapshots (
            node_id text primary key,
            source_id uuid null references node_sources(id) on delete set null,
            signer_agent_did text not null,
            public_key text not null,
            generated_at bigint not null,
            ingested_at timestamptz not null default now(),
            payload jsonb not null,
            signature text not null
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_node_snapshots_node_id on node_snapshots(node_id);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create table if not exists gateway_registry_entries (
            gateway_id text primary key,
            display_name text not null,
            base_url text not null unique,
            public_key text not null,
            region text null,
            operator_did text null,
            roles jsonb not null default '[]'::jsonb,
            supported_endpoints jsonb not null default '[]'::jsonb,
            federation_peers jsonb not null default '[]'::jsonb,
            allows_public_ingest boolean not null default false,
            manifest_payload jsonb not null,
            manifest_signature text not null,
            status text not null default 'pending',
            discovery_tier text not null default 'community',
            review_reason text null,
            reviewed_at timestamptz null,
            reviewed_by text null,
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now()
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        do $$
        begin
            if exists (
                select 1
                from information_schema.columns
                where table_name = 'node_sources' and column_name = 'expected_signer_agent_id'
            ) and not exists (
                select 1
                from information_schema.columns
                where table_name = 'node_sources' and column_name = 'expected_signer_agent_did'
            ) then
                alter table node_sources
                rename column expected_signer_agent_id to expected_signer_agent_did;
            end if;
        end
        $$;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        do $$
        begin
            if exists (
                select 1
                from information_schema.columns
                where table_name = 'node_snapshots' and column_name = 'signer_agent_id'
            ) and not exists (
                select 1
                from information_schema.columns
                where table_name = 'node_snapshots' and column_name = 'signer_agent_did'
            ) then
                alter table node_snapshots
                rename column signer_agent_id to signer_agent_did;
            end if;
        end
        $$;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        do $$
        begin
            if exists (
                select 1
                from information_schema.columns
                where table_name = 'gateway_registry_entries' and column_name = 'operator_id'
            ) and not exists (
                select 1
                from information_schema.columns
                where table_name = 'gateway_registry_entries' and column_name = 'operator_did'
            ) then
                alter table gateway_registry_entries
                rename column operator_id to operator_did;
            end if;
        end
        $$;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_registry_entries_status on gateway_registry_entries(status);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        create index if not exists idx_gateway_registry_entries_tier on gateway_registry_entries(discovery_tier);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_node_source(pool: &PgPool, record: InsertNodeSourceRecord<'_>) -> Result<()> {
    sqlx::query(
        r#"
        insert into node_sources (
            id, name, export_url, wattetheria_snapshot_export_url,
            wattetheria_events_export_url, wattswarm_ui_base_url,
            wattswarm_sync_grpc_endpoint, region, expected_signer_agent_did,
            expected_wattswarm_node_id, source_status, transport_capabilities,
            transport_contact_material, created_at, updated_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), now())
        "#,
    )
    .bind(record.id)
    .bind(record.name)
    .bind(record.export_url)
    .bind(record.wattetheria_snapshot_export_url)
    .bind(record.wattetheria_events_export_url)
    .bind(record.wattswarm_ui_base_url)
    .bind(record.wattswarm_sync_grpc_endpoint)
    .bind(record.region)
    .bind(record.expected_signer_agent_did)
    .bind(record.expected_wattswarm_node_id)
    .bind(record.source_status)
    .bind(record.transport_capabilities)
    .bind(record.transport_contact_material)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_node_sources(pool: &PgPool) -> Result<Vec<NodeSourceRow>> {
    Ok(sqlx::query_as::<_, NodeSourceRow>(
        r#"
        select
            id,
            name,
            export_url,
            wattetheria_snapshot_export_url,
            wattetheria_events_export_url,
            wattswarm_ui_base_url,
            wattswarm_sync_grpc_endpoint,
            region,
            expected_signer_agent_did,
            expected_wattswarm_node_id,
            source_status,
            created_at,
            updated_at,
            last_sync_at,
            last_sync_status,
            last_error,
            transport_capabilities,
            transport_contact_material
        from node_sources
        order by created_at asc
        "#,
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_node_source(pool: &PgPool, source_id: Uuid) -> Result<Option<NodeSourceRow>> {
    Ok(sqlx::query_as::<_, NodeSourceRow>(
        r#"
        select
            id,
            name,
            export_url,
            wattetheria_snapshot_export_url,
            wattetheria_events_export_url,
            wattswarm_ui_base_url,
            wattswarm_sync_grpc_endpoint,
            region,
            expected_signer_agent_did,
            expected_wattswarm_node_id,
            source_status,
            created_at,
            updated_at,
            last_sync_at,
            last_sync_status,
            last_error,
            transport_capabilities,
            transport_contact_material
        from node_sources
        where id = $1
        "#,
    )
    .bind(source_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn find_node_source_for_identity(
    pool: &PgPool,
    node_id: &str,
    signer_agent_did: &str,
) -> Result<Option<NodeSourceRow>> {
    let matches = sqlx::query_as::<_, NodeSourceRow>(
        r#"
        select
            id,
            name,
            export_url,
            wattetheria_snapshot_export_url,
            wattetheria_events_export_url,
            wattswarm_ui_base_url,
            wattswarm_sync_grpc_endpoint,
            region,
            expected_signer_agent_did,
            expected_wattswarm_node_id,
            source_status,
            created_at,
            updated_at,
            last_sync_at,
            last_sync_status,
            last_error,
            transport_capabilities,
            transport_contact_material
        from node_sources
        where expected_signer_agent_did = $1
           or expected_wattswarm_node_id = $2
        order by
            case
                when expected_signer_agent_did = $1 then 0
                when expected_wattswarm_node_id = $2 then 1
                else 2
            end,
            created_at asc
        limit 2
        "#,
    )
    .bind(signer_agent_did)
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    Ok(matches.first().cloned())
}

pub async fn update_source_sync_status(
    pool: &PgPool,
    source_id: Uuid,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        update node_sources
        set
            updated_at = now(),
            last_sync_at = now(),
            last_sync_status = $2,
            last_error = $3
        where id = $1
        "#,
    )
    .bind(source_id)
    .bind(status)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_snapshot(pool: &PgPool, record: UpsertSnapshotRecord<'_>) -> Result<bool> {
    let result = sqlx::query(
        r#"
        insert into node_snapshots (
            node_id, source_id, signer_agent_did, public_key, generated_at, ingested_at, payload, signature
        )
        values ($1, $2, $3, $4, $5, now(), $6, $7)
        on conflict (node_id) do update
        set
            source_id = coalesce(excluded.source_id, node_snapshots.source_id),
            signer_agent_did = excluded.signer_agent_did,
            public_key = excluded.public_key,
            generated_at = excluded.generated_at,
            ingested_at = now(),
            payload = excluded.payload,
            signature = excluded.signature
        where excluded.generated_at >= node_snapshots.generated_at
        "#,
    )
    .bind(record.node_id)
    .bind(record.source_id)
    .bind(record.signer_agent_did)
    .bind(record.public_key)
    .bind(record.generated_at)
    .bind(sqlx::types::Json(record.payload))
    .bind(record.signature)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_snapshots(pool: &PgPool) -> Result<Vec<SnapshotRow>> {
    Ok(sqlx::query_as::<_, SnapshotRow>(
        r#"
        select
            source_id,
            node_id,
            signer_agent_did,
            public_key,
            generated_at,
            ingested_at,
            payload,
            signature
        from node_snapshots
        order by ingested_at desc
        "#,
    )
    .fetch_all(pool)
    .await?)
}

pub async fn list_visible_snapshots(pool: &PgPool) -> Result<Vec<SnapshotRow>> {
    Ok(sqlx::query_as::<_, SnapshotRow>(
        r#"
        select
            source_id,
            node_id,
            signer_agent_did,
            public_key,
            generated_at,
            ingested_at,
            payload,
            signature
        from node_snapshots
        where source_id is null
           or exists (
                select 1
                from node_sources
                where node_sources.id = node_snapshots.source_id
                  and node_sources.source_status = 'active'
           )
        order by ingested_at desc
        "#,
    )
    .fetch_all(pool)
    .await?)
}

pub async fn counts(pool: &PgPool) -> Result<GatewayHealthCounts> {
    let row = sqlx::query(
        r#"
        select
            (select count(*) from node_sources) as source_count,
            (select count(*) from node_sources where source_status = 'active') as active_source_count,
            (select count(*) from node_snapshots) as snapshot_count,
            (select count(*) from gateway_projection_rows) as projection_count,
            (select count(*) from gateway_ui_events) as ui_event_count,
            (select count(*) from gateway_ingest_audit where record_kind = 'gap_snapshot_refresh_applied') as backfill_event_count
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(GatewayHealthCounts {
        source_count: row.try_get("source_count")?,
        active_source_count: row.try_get("active_source_count")?,
        snapshot_count: row.try_get("snapshot_count")?,
        projection_count: row.try_get("projection_count")?,
        ui_event_count: row.try_get("ui_event_count")?,
        backfill_event_count: row.try_get("backfill_event_count")?,
    })
}

pub async fn upsert_projection_row(
    pool: &PgPool,
    record: UpsertProjectionRecord<'_>,
) -> Result<()> {
    sqlx::query(
        r#"
        insert into gateway_projection_rows (
            data_kind, identity_key, source_node_id, source_id, generated_at,
            ingested_at, visibility, payload, provenance
        )
        values ($1, $2, $3, $4, $5, now(), $6, $7, $8)
        on conflict (data_kind, identity_key, source_node_id) do update
        set
            source_id = coalesce(excluded.source_id, gateway_projection_rows.source_id),
            generated_at = excluded.generated_at,
            ingested_at = now(),
            visibility = excluded.visibility,
            payload = excluded.payload,
            provenance = excluded.provenance
        where excluded.generated_at >= gateway_projection_rows.generated_at
        "#,
    )
    .bind(record.data_kind)
    .bind(record.identity_key)
    .bind(record.source_node_id)
    .bind(record.source_id)
    .bind(record.generated_at)
    .bind(record.visibility)
    .bind(sqlx::types::Json(record.payload))
    .bind(sqlx::types::Json(record.provenance))
    .execute(pool)
    .await?;
    insert_audit_record(
        pool,
        InsertAuditRecord {
            record_kind: "projection_upsert",
            data_kind: Some(record.data_kind),
            identity_key: Some(record.identity_key),
            source_id: record.source_id,
            source_node_id: Some(record.source_node_id),
            generated_at: Some(record.generated_at),
            ingest_path: record
                .provenance
                .get("ingest_path")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            payload: record.payload,
            provenance: record.provenance,
        },
    )
    .await?;
    Ok(())
}

pub async fn list_projection_rows(pool: &PgPool, data_kind: &str) -> Result<Vec<ProjectionRow>> {
    Ok(sqlx::query_as::<_, ProjectionRow>(
        r#"
        select
            data_kind,
            identity_key,
            source_node_id,
            source_id,
            generated_at,
            ingested_at,
            visibility,
            payload,
            provenance
        from gateway_projection_rows
        where data_kind = $1
          and (
            source_id is null
            or exists (
                select 1
                from node_sources
                where node_sources.id = gateway_projection_rows.source_id
                  and node_sources.source_status = 'active'
            )
          )
        order by generated_at desc, source_node_id asc
        "#,
    )
    .bind(data_kind)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_ui_event(
    pool: &PgPool,
    record: InsertUiEventRecord<'_>,
) -> Result<Option<UiEventRow>> {
    let row = sqlx::query_as::<_, UiEventRow>(
        r#"
        insert into gateway_ui_events (
            event_id, source_id, node_id, signer_agent_did, data_kind, event_kind,
            visibility, provisional, topic_id, organization_id, task_id,
            generated_at, payload, ingest_path, source_cursor_or_seq
        )
        values (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11,
            $12, $13, $14, $15
        )
        on conflict (event_id) do nothing
        returning
            cursor,
            event_id,
            source_id,
            node_id,
            signer_agent_did,
            data_kind,
            event_kind,
            visibility,
            provisional,
            topic_id,
            organization_id,
            task_id,
            generated_at,
            ingested_at,
            payload,
            ingest_path,
            source_cursor_or_seq
        "#,
    )
    .bind(record.event_id)
    .bind(record.source_id)
    .bind(record.node_id)
    .bind(record.signer_agent_did)
    .bind(record.data_kind)
    .bind(record.event_kind)
    .bind(record.visibility)
    .bind(record.provisional)
    .bind(record.topic_id)
    .bind(record.organization_id)
    .bind(record.task_id)
    .bind(record.generated_at)
    .bind(sqlx::types::Json(record.payload))
    .bind(record.ingest_path)
    .bind(record.source_cursor_or_seq)
    .fetch_optional(pool)
    .await?;
    if row.is_some() {
        let provenance = serde_json::json!({
            "source_cursor_or_seq": record.source_cursor_or_seq,
            "visibility": record.visibility,
            "provisional": record.provisional,
        });
        insert_audit_record(
            pool,
            InsertAuditRecord {
                record_kind: "ui_event_insert",
                data_kind: Some(record.data_kind),
                identity_key: Some(record.event_id),
                source_id: record.source_id,
                source_node_id: Some(record.node_id),
                generated_at: Some(record.generated_at),
                ingest_path: record.ingest_path,
                payload: record.payload,
                provenance: &provenance,
            },
        )
        .await?;
    }
    Ok(row)
}

pub async fn list_ui_events_after(
    pool: &PgPool,
    query: ListUiEventsQuery<'_>,
) -> Result<Vec<UiEventRow>> {
    Ok(sqlx::query_as::<_, UiEventRow>(
        r#"
        select
            cursor,
            event_id,
            source_id,
            node_id,
            signer_agent_did,
            data_kind,
            event_kind,
            visibility,
            provisional,
            topic_id,
            organization_id,
            task_id,
            generated_at,
            ingested_at,
            payload,
            ingest_path,
            source_cursor_or_seq
        from gateway_ui_events
        where cursor > $1
          and (
            source_id is null
            or exists (
                select 1
                from node_sources
                where node_sources.id = gateway_ui_events.source_id
                  and node_sources.source_status = 'active'
            )
          )
          and ($2::text is null or data_kind = $2)
          and ($3::text is null or node_id = $3)
          and ($4::text is null or topic_id = $4)
          and ($5::text is null or organization_id = $5)
          and ($6::text is null or task_id = $6)
        order by cursor asc
        limit $7
        "#,
    )
    .bind(query.cursor)
    .bind(query.data_kind)
    .bind(query.node_id)
    .bind(query.topic_id)
    .bind(query.organization_id)
    .bind(query.task_id)
    .bind(query.limit.max(1))
    .fetch_all(pool)
    .await?)
}

pub async fn earliest_ui_event_cursor(pool: &PgPool) -> Result<Option<i64>> {
    let row = sqlx::query(
        r#"
        select min(cursor) as earliest_cursor
        from gateway_ui_events
        where source_id is null
           or exists (
                select 1
                from node_sources
                where node_sources.id = gateway_ui_events.source_id
                  and node_sources.source_status = 'active'
           )
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.try_get("earliest_cursor")?)
}

pub async fn upsert_gateway_manifest(
    pool: &PgPool,
    record: UpsertGatewayManifestRecord<'_>,
) -> Result<GatewayRegistryEntry> {
    let payload = &record.manifest.payload;
    sqlx::query(
        r#"
        insert into gateway_registry_entries (
            gateway_id,
            display_name,
            base_url,
            public_key,
            region,
            operator_did,
            roles,
            supported_endpoints,
            federation_peers,
            allows_public_ingest,
            manifest_payload,
            manifest_signature,
            status,
            discovery_tier,
            created_at,
            updated_at
        )
        values (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', 'community', now(), now()
        )
        on conflict (gateway_id) do update
        set
            display_name = excluded.display_name,
            base_url = excluded.base_url,
            public_key = excluded.public_key,
            region = excluded.region,
            operator_did = excluded.operator_did,
            roles = excluded.roles,
            supported_endpoints = excluded.supported_endpoints,
            federation_peers = excluded.federation_peers,
            allows_public_ingest = excluded.allows_public_ingest,
            manifest_payload = excluded.manifest_payload,
            manifest_signature = excluded.manifest_signature,
            updated_at = now()
        "#,
    )
    .bind(&payload.gateway_id)
    .bind(&payload.display_name)
    .bind(&payload.base_url)
    .bind(&payload.public_key)
    .bind(payload.region.as_deref())
    .bind(payload.operator_did.as_deref())
    .bind(sqlx::types::Json(&payload.roles))
    .bind(sqlx::types::Json(&payload.supported_endpoints))
    .bind(sqlx::types::Json(&payload.federation_peers))
    .bind(payload.allows_public_ingest)
    .bind(sqlx::types::Json(payload))
    .bind(&record.manifest.signature)
    .execute(pool)
    .await?;

    get_gateway_registry_entry(pool, &payload.gateway_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("registered gateway entry missing after upsert"))
}

pub async fn review_gateway_manifest(
    pool: &PgPool,
    gateway_id: &str,
    status: &str,
    discovery_tier: &str,
    reason: Option<&str>,
    reviewed_by: Option<&str>,
) -> Result<Option<GatewayRegistryEntry>> {
    sqlx::query(
        r#"
        update gateway_registry_entries
        set
            status = $2,
            discovery_tier = $3,
            review_reason = $4,
            reviewed_by = $5,
            reviewed_at = now(),
            updated_at = now()
        where gateway_id = $1
        "#,
    )
    .bind(gateway_id)
    .bind(status)
    .bind(discovery_tier)
    .bind(reason)
    .bind(reviewed_by)
    .execute(pool)
    .await?;
    get_gateway_registry_entry(pool, gateway_id).await
}

pub async fn insert_audit_record(pool: &PgPool, record: InsertAuditRecord<'_>) -> Result<()> {
    sqlx::query(
        r#"
        insert into gateway_ingest_audit (
            record_kind,
            data_kind,
            identity_key,
            source_id,
            source_node_id,
            generated_at,
            ingest_path,
            payload,
            provenance,
            created_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
        "#,
    )
    .bind(record.record_kind)
    .bind(record.data_kind)
    .bind(record.identity_key)
    .bind(record.source_id)
    .bind(record.source_node_id)
    .bind(record.generated_at)
    .bind(record.ingest_path)
    .bind(sqlx::types::Json(record.payload))
    .bind(sqlx::types::Json(record.provenance))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_gateway_registry_entries(
    pool: &PgPool,
    status: Option<&str>,
    tier: Option<&str>,
    region: Option<&str>,
    role: Option<&str>,
) -> Result<Vec<GatewayRegistryEntry>> {
    let rows = sqlx::query_as::<_, GatewayRegistryDbRow>(
        r#"
        select
            gateway_id,
            display_name,
            base_url,
            public_key,
            region,
            operator_did,
            roles,
            supported_endpoints,
            federation_peers,
            allows_public_ingest,
            manifest_payload,
            manifest_signature,
            status,
            discovery_tier,
            review_reason,
            reviewed_at,
            reviewed_by,
            created_at,
            updated_at
        from gateway_registry_entries
        where ($1::text is null or status = $1)
          and ($2::text is null or discovery_tier = $2)
          and ($3::text is null or region = $3)
          and ($4::text is null or roles ? $4)
        order by
            case status when 'approved' then 0 else 1 end,
            case discovery_tier
                when 'official' then 0
                when 'verified' then 1
                when 'community' then 2
                when 'manual' then 3
                else 4
            end,
            updated_at desc
        "#,
    )
    .bind(status)
    .bind(tier)
    .bind(region)
    .bind(role)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn get_gateway_registry_entry(
    pool: &PgPool,
    gateway_id: &str,
) -> Result<Option<GatewayRegistryEntry>> {
    let row = sqlx::query_as::<_, GatewayRegistryDbRow>(
        r#"
        select
            gateway_id,
            display_name,
            base_url,
            public_key,
            region,
            operator_did,
            roles,
            supported_endpoints,
            federation_peers,
            allows_public_ingest,
            manifest_payload,
            manifest_signature,
            status,
            discovery_tier,
            review_reason,
            reviewed_at,
            reviewed_by,
            created_at,
            updated_at
        from gateway_registry_entries
        where gateway_id = $1
        "#,
    )
    .bind(gateway_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}
