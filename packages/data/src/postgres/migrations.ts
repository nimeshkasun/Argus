import { type Kysely, type Migration, type MigrationProvider, sql } from 'kysely';

// Migrations use snake_case identifiers explicitly. They are append-only: never edit a shipped migration.
const migrations: Record<string, Migration> = {
  '0001_init': {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async up(db: Kysely<any>) {
      await db.schema
        .createTable('users')
        .addColumn('id', 'uuid', (c) => c.primaryKey())
        .addColumn('username', 'text', (c) => c.notNull())
        .addColumn('username_lower', 'text', (c) => c.notNull().unique())
        .addColumn('email', 'text')
        .addColumn('email_lower', 'text', (c) => c.unique())
        .addColumn('display_name', 'text', (c) => c.notNull())
        .addColumn('password_hash', 'text', (c) => c.notNull())
        .addColumn('role', 'text', (c) => c.notNull())
        .addColumn('status', 'text', (c) => c.notNull())
        .addColumn('must_change_password', 'boolean', (c) => c.notNull().defaultTo(false))
        .addColumn('mfa_enabled', 'boolean', (c) => c.notNull().defaultTo(false))
        .addColumn('mfa_secret_enc', 'text')
        .addColumn('mfa_pending_secret_enc', 'text')
        .addColumn('mfa_recovery_codes', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
        .addColumn('mfa_last_used_step', 'integer')
        .addColumn('failed_login_count', 'integer', (c) => c.notNull().defaultTo(0))
        .addColumn('locked_until', 'timestamptz')
        .addColumn('last_login_at', 'timestamptz')
        .addColumn('password_changed_at', 'timestamptz')
        .addColumn('created_at', 'timestamptz', (c) => c.notNull())
        .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
        .execute();

      await db.schema
        .createTable('teams')
        .addColumn('id', 'uuid', (c) => c.primaryKey())
        .addColumn('name', 'text', (c) => c.notNull())
        .addColumn('name_lower', 'text', (c) => c.notNull().unique())
        .addColumn('description', 'text')
        .addColumn('created_at', 'timestamptz', (c) => c.notNull())
        .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
        .execute();

      await db.schema
        .createTable('team_members')
        .addColumn('team_id', 'uuid', (c) => c.notNull().references('teams.id').onDelete('cascade'))
        .addColumn('user_id', 'uuid', (c) => c.notNull().references('users.id').onDelete('cascade'))
        .addPrimaryKeyConstraint('team_members_pk', ['team_id', 'user_id'])
        .execute();
      await db.schema.createIndex('team_members_user_idx').on('team_members').column('user_id').execute();

      await db.schema
        .createTable('sessions')
        .addColumn('id', 'uuid', (c) => c.primaryKey())
        .addColumn('user_id', 'uuid', (c) => c.notNull().references('users.id').onDelete('cascade'))
        .addColumn('token_hash', 'text', (c) => c.notNull().unique())
        .addColumn('family_id', 'uuid', (c) => c.notNull())
        .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
        .addColumn('revoked_at', 'timestamptz')
        .addColumn('created_at', 'timestamptz', (c) => c.notNull())
        .addColumn('last_used_at', 'timestamptz')
        .addColumn('user_agent', 'text')
        .addColumn('ip', 'text')
        .execute();
      await db.schema.createIndex('sessions_user_idx').on('sessions').column('user_id').execute();
      await db.schema.createIndex('sessions_family_idx').on('sessions').column('family_id').execute();
      await db.schema.createIndex('sessions_expires_idx').on('sessions').column('expires_at').execute();

      await db.schema
        .createTable('audit_logs')
        .addColumn('id', 'uuid', (c) => c.primaryKey())
        .addColumn('at', 'timestamptz', (c) => c.notNull())
        .addColumn('actor_id', 'uuid')
        .addColumn('actor_name', 'text')
        .addColumn('action', 'text', (c) => c.notNull())
        .addColumn('target_type', 'text')
        .addColumn('target_id', 'text')
        .addColumn('ip', 'text')
        .addColumn('outcome', 'text', (c) => c.notNull())
        .addColumn('details', 'jsonb')
        .execute();
      await db.schema.createIndex('audit_logs_at_idx').on('audit_logs').column('at desc').execute();
      await db.schema.createIndex('audit_logs_actor_idx').on('audit_logs').columns(['actor_id', 'at desc']).execute();
      await db.schema.createIndex('audit_logs_action_idx').on('audit_logs').columns(['action', 'at desc']).execute();
      await db.schema.createIndex('audit_logs_target_idx').on('audit_logs').columns(['target_type', 'target_id']).execute();

      await db.schema
        .createTable('settings')
        .addColumn('key', 'text', (c) => c.primaryKey())
        .addColumn('value', 'jsonb', (c) => c.notNull())
        .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
        .addColumn('updated_by', 'uuid')
        .execute();
    },
  },
};

migrations['0002_sources_repos_jobs'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('sources')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('provider', 'text', (c) => c.notNull())
      .addColumn('base_url', 'text')
      .addColumn('scope', 'text')
      .addColumn('username', 'text')
      .addColumn('token_enc', 'text', (c) => c.notNull())
      .addColumn('token_last4', 'text', (c) => c.notNull())
      .addColumn('webhook_secret_enc', 'text', (c) => c.notNull())
      .addColumn('auto_activate_pattern', 'text')
      .addColumn('default_team_id', 'uuid', (c) => c.references('teams.id').onDelete('set null'))
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('last_sync_at', 'timestamptz')
      .addColumn('last_sync_error', 'text')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .execute();

    await db.schema
      .createTable('repositories')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('source_id', 'uuid', (c) => c.notNull().references('sources.id').onDelete('cascade'))
      .addColumn('external_id', 'text', (c) => c.notNull())
      .addColumn('full_name', 'text', (c) => c.notNull())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('html_url', 'text')
      .addColumn('clone_url', 'text', (c) => c.notNull())
      .addColumn('default_branch', 'text')
      .addColumn('visibility', 'text', (c) => c.notNull())
      .addColumn('language', 'text')
      .addColumn('description', 'text')
      .addColumn('archived', 'boolean', (c) => c.notNull().defaultTo(false))
      .addColumn('last_pushed_at', 'timestamptz')
      .addColumn('removed_at', 'timestamptz')
      .addColumn('active', 'boolean', (c) => c.notNull().defaultTo(false))
      .addColumn('team_id', 'uuid', (c) => c.references('teams.id').onDelete('set null'))
      .addColumn('criticality', 'text', (c) => c.notNull())
      .addColumn('branch', 'text')
      .addColumn('schedule', 'jsonb', (c) => c.notNull())
      .addColumn('scan_on_push', 'boolean', (c) => c.notNull().defaultTo(true))
      .addColumn('jira_project_key', 'text')
      .addColumn('notify_emails', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('next_scan_at', 'timestamptz')
      .addColumn('last_scan_at', 'timestamptz')
      .addColumn('last_scan_status', 'text')
      .addColumn('last_scan_run_id', 'uuid')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .addUniqueConstraint('repositories_source_external_unique', ['source_id', 'external_id'])
      .execute();
    await db.schema.createIndex('repositories_due_idx').on('repositories').columns(['active', 'next_scan_at']).execute();
    await db.schema.createIndex('repositories_team_idx').on('repositories').column('team_id').execute();
    await db.schema.createIndex('repositories_full_name_idx').on('repositories').column('full_name').execute();

    await db.schema
      .createTable('scan_runs')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('source_id', 'uuid', (c) => c.notNull())
      .addColumn('team_id', 'uuid')
      .addColumn('trigger', 'text', (c) => c.notNull())
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('requested_by', 'uuid')
      .addColumn('branch', 'text')
      .addColumn('commit_sha', 'text')
      .addColumn('attempts', 'integer', (c) => c.notNull().defaultTo(0))
      .addColumn('queued_at', 'timestamptz', (c) => c.notNull())
      .addColumn('started_at', 'timestamptz')
      .addColumn('finished_at', 'timestamptz')
      .addColumn('duration_ms', 'integer')
      .addColumn('error', 'text')
      .addColumn('stats', 'jsonb')
      .addColumn('log', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .execute();
    await db.schema.createIndex('scan_runs_repo_idx').on('scan_runs').columns(['repo_id', 'queued_at desc']).execute();
    await db.schema.createIndex('scan_runs_queued_idx').on('scan_runs').column('queued_at desc').execute();
    await db.schema.createIndex('scan_runs_status_idx').on('scan_runs').column('status').execute();

    await db.schema
      .createTable('jobs')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('type', 'text', (c) => c.notNull())
      .addColumn('payload', 'jsonb', (c) => c.notNull())
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('priority', 'integer', (c) => c.notNull().defaultTo(0))
      .addColumn('run_at', 'timestamptz', (c) => c.notNull())
      .addColumn('attempts', 'integer', (c) => c.notNull().defaultTo(0))
      .addColumn('max_attempts', 'integer', (c) => c.notNull())
      .addColumn('locked_by', 'text')
      .addColumn('locked_until', 'timestamptz')
      .addColumn('last_error', 'text')
      .addColumn('dedupe_key', 'text')
      .addColumn('active_dedupe_key', 'text', (c) => c.unique())
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .addColumn('finished_at', 'timestamptz')
      .execute();
    await db.schema.createIndex('jobs_runnable_idx').on('jobs').columns(['status', 'type', 'run_at']).execute();
    await db.schema.createIndex('jobs_finished_idx').on('jobs').column('finished_at').execute();

    await db.schema
      .createTable('locks')
      .addColumn('name', 'text', (c) => c.primaryKey())
      .addColumn('owner', 'text', (c) => c.notNull())
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .execute();
  },
};

migrations['0003_findings'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .alterTable('repositories')
      .addColumn('disabled_scanners', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .execute();

    await db.schema
      .createTable('findings')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('source_id', 'uuid', (c) => c.notNull())
      .addColumn('team_id', 'uuid')
      .addColumn('scanner', 'text', (c) => c.notNull())
      .addColumn('rule_id', 'text', (c) => c.notNull())
      .addColumn('fingerprint', 'text', (c) => c.notNull())
      .addColumn('title', 'text', (c) => c.notNull())
      .addColumn('description', 'text')
      .addColumn('severity', 'text', (c) => c.notNull())
      .addColumn('risk_score', 'integer', (c) => c.notNull())
      .addColumn('risk_factors', 'jsonb', (c) => c.notNull())
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('path', 'text')
      .addColumn('line', 'integer')
      .addColumn('package_ecosystem', 'text')
      .addColumn('package_name', 'text')
      .addColumn('package', 'jsonb')
      .addColumn('advisory', 'jsonb')
      .addColumn('secret', 'jsonb')
      .addColumn('details', 'jsonb')
      .addColumn('remediation', 'text')
      .addColumn('suppression_id', 'uuid')
      .addColumn('first_seen_at', 'timestamptz', (c) => c.notNull())
      .addColumn('last_seen_at', 'timestamptz', (c) => c.notNull())
      .addColumn('first_run_id', 'uuid', (c) => c.notNull())
      .addColumn('last_run_id', 'uuid', (c) => c.notNull())
      .addColumn('fixed_at', 'timestamptz')
      .addUniqueConstraint('findings_repo_fingerprint_unique', ['repo_id', 'fingerprint'])
      .execute();
    await db.schema.createIndex('findings_status_score_idx').on('findings').columns(['status', 'risk_score desc']).execute();
    await db.schema.createIndex('findings_team_idx').on('findings').columns(['team_id', 'status']).execute();
    await db.schema.createIndex('findings_repo_status_idx').on('findings').columns(['repo_id', 'status']).execute();
    await db.schema.createIndex('findings_package_idx').on('findings').columns(['package_ecosystem', 'package_name']).execute();

    await db.schema
      .createTable('dependencies')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('team_id', 'uuid')
      .addColumn('ecosystem', 'text', (c) => c.notNull())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('name_lower', 'text', (c) => c.notNull())
      .addColumn('version', 'text', (c) => c.notNull())
      .addColumn('direct', 'boolean', (c) => c.notNull())
      .addColumn('dev', 'boolean', (c) => c.notNull())
      .addColumn('license', 'text')
      .addColumn('manifest_path', 'text', (c) => c.notNull())
      .addColumn('latest_version', 'text')
      .addColumn('deprecated', 'text')
      .addColumn('vulnerabilities', 'integer', (c) => c.notNull().defaultTo(0))
      .execute();
    await db.schema.createIndex('dependencies_repo_idx').on('dependencies').column('repo_id').execute();
    await db.schema.createIndex('dependencies_name_idx').on('dependencies').columns(['name_lower', 'ecosystem']).execute();

    await db.schema
      .createTable('suppressions')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('repo_id', 'uuid', (c) => c.references('repositories.id').onDelete('cascade'))
      .addColumn('scanner', 'text')
      .addColumn('rule_id', 'text')
      .addColumn('path_pattern', 'text')
      .addColumn('package_name', 'text')
      .addColumn('reason', 'text', (c) => c.notNull())
      .addColumn('expires_at', 'timestamptz')
      .addColumn('created_by', 'uuid')
      .addColumn('created_by_name', 'text')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('suppressions_repo_idx').on('suppressions').column('repo_id').execute();

    await db.schema
      .createTable('intel_cache')
      .addColumn('key', 'text', (c) => c.primaryKey())
      .addColumn('value', 'jsonb', (c) => c.notNull())
      .addColumn('fetched_at', 'timestamptz', (c) => c.notNull())
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('intel_cache_expires_idx').on('intel_cache').column('expires_at').execute();
  },
};

migrations['0004_tickets'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('tickets')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('key', 'text', (c) => c.notNull().unique())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('source_id', 'uuid', (c) => c.notNull())
      .addColumn('team_id', 'uuid')
      .addColumn('scanner', 'text', (c) => c.notNull())
      .addColumn('group_key', 'text', (c) => c.notNull())
      .addColumn('title', 'text', (c) => c.notNull())
      .addColumn('description', 'text')
      .addColumn('severity', 'text', (c) => c.notNull())
      .addColumn('risk_score', 'integer', (c) => c.notNull())
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('assignee_id', 'uuid', (c) => c.references('users.id').onDelete('set null'))
      .addColumn('watcher_ids', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('labels', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('finding_ids', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('open_findings', 'integer', (c) => c.notNull().defaultTo(0))
      .addColumn('remediation', 'text')
      .addColumn('due_at', 'timestamptz')
      .addColumn('sla_breached_at', 'timestamptz')
      .addColumn('suppression_id', 'uuid')
      .addColumn('jira', 'jsonb')
      .addColumn('resolved_at', 'timestamptz')
      .addColumn('closed_at', 'timestamptz')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .addColumn('last_activity_at', 'timestamptz', (c) => c.notNull())
      .addUniqueConstraint('tickets_repo_group_unique', ['repo_id', 'group_key'])
      .execute();
    await db.schema.createIndex('tickets_status_score_idx').on('tickets').columns(['status', 'risk_score desc']).execute();
    await db.schema.createIndex('tickets_team_idx').on('tickets').columns(['team_id', 'status']).execute();
    await db.schema.createIndex('tickets_assignee_idx').on('tickets').columns(['assignee_id', 'status']).execute();
    await db.schema.createIndex('tickets_due_idx').on('tickets').columns(['status', 'due_at']).execute();

    await db.schema
      .createTable('ticket_events')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('ticket_id', 'uuid', (c) => c.notNull().references('tickets.id').onDelete('cascade'))
      .addColumn('type', 'text', (c) => c.notNull())
      .addColumn('actor_id', 'uuid')
      .addColumn('actor_name', 'text')
      .addColumn('body', 'text')
      .addColumn('data', 'jsonb')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('ticket_events_ticket_idx').on('ticket_events').columns(['ticket_id', 'created_at']).execute();

    await db.schema
      .createTable('counters')
      .addColumn('name', 'text', (c) => c.primaryKey())
      .addColumn('value', 'bigint', (c) => c.notNull())
      .execute();

    await db.schema
      .createTable('notification_channels')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('type', 'text', (c) => c.notNull())
      .addColumn('enabled', 'boolean', (c) => c.notNull())
      .addColumn('config', 'jsonb', (c) => c.notNull())
      .addColumn('secret_enc', 'text')
      .addColumn('secret_hint', 'text')
      .addColumn('last_used_at', 'timestamptz')
      .addColumn('last_error', 'text')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .execute();

    await db.schema
      .createTable('notification_rules')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('enabled', 'boolean', (c) => c.notNull())
      .addColumn('events', 'jsonb', (c) => c.notNull())
      .addColumn('min_severity', 'text', (c) => c.notNull())
      .addColumn('team_ids', 'jsonb', (c) => c.notNull())
      .addColumn('channel_ids', 'jsonb', (c) => c.notNull())
      .addColumn('recipients', 'jsonb', (c) => c.notNull())
      .addColumn('include_repo_recipients', 'boolean', (c) => c.notNull())
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .execute();

    await db.schema.alterTable('findings').addColumn('ticket_id', 'uuid').execute();
    await db.schema.alterTable('suppressions').addColumn('group_key', 'text').addColumn('ticket_id', 'uuid').execute();
    await db.schema.createIndex('findings_ticket_idx').on('findings').column('ticket_id').execute();
  },
};

migrations['0005_ai'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema.alterTable('repositories').addColumn('ai_enabled', 'boolean', (c) => c.notNull().defaultTo(true)).execute();

    // No foreign keys: usage is kept for cost reporting after repositories and users are deleted.
    await db.schema
      .createTable('ai_usage')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('at', 'timestamptz', (c) => c.notNull())
      .addColumn('provider', 'text', (c) => c.notNull())
      .addColumn('model', 'text', (c) => c.notNull())
      .addColumn('use_case', 'text', (c) => c.notNull())
      .addColumn('user_id', 'uuid')
      .addColumn('repo_id', 'uuid')
      .addColumn('input_tokens', 'integer', (c) => c.notNull())
      .addColumn('output_tokens', 'integer', (c) => c.notNull())
      .addColumn('cost_usd', 'double precision', (c) => c.notNull())
      .addColumn('outcome', 'text', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('ai_usage_at_idx').on('ai_usage').column('at').execute();

    await db.schema
      .createTable('ai_insights')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('subject_type', 'text', (c) => c.notNull())
      .addColumn('subject_id', 'uuid', (c) => c.notNull())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('use_case', 'text', (c) => c.notNull())
      .addColumn('provider', 'text', (c) => c.notNull())
      .addColumn('model', 'text', (c) => c.notNull())
      .addColumn('output', 'jsonb', (c) => c.notNull())
      .addColumn('redactions', 'integer', (c) => c.notNull())
      .addColumn('created_by', 'uuid')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addUniqueConstraint('ai_insights_subject_unique', ['subject_type', 'subject_id', 'use_case'])
      .execute();
    await db.schema.createIndex('ai_insights_repo_idx').on('ai_insights').column('repo_id').execute();
  },
};

migrations['0006_intel'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('intel_sources')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('url', 'text', (c) => c.notNull())
      .addColumn('enabled', 'boolean', (c) => c.notNull())
      .addColumn('interval_minutes', 'integer', (c) => c.notNull())
      .addColumn('last_fetched_at', 'timestamptz')
      .addColumn('last_error', 'text')
      .addColumn('last_new_items', 'integer')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .execute();

    await db.schema
      .createTable('intel_items')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('source_id', 'uuid', (c) => c.notNull().references('intel_sources.id').onDelete('cascade'))
      .addColumn('guid', 'text', (c) => c.notNull())
      .addColumn('title', 'text', (c) => c.notNull())
      .addColumn('link', 'text')
      .addColumn('published_at', 'timestamptz')
      .addColumn('summary', 'text', (c) => c.notNull())
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('candidates', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('extraction', 'jsonb')
      .addColumn('error', 'text')
      .addColumn('advisory_ids', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('reviewed_by', 'uuid')
      .addColumn('reviewed_at', 'timestamptz')
      .addColumn('fetched_at', 'timestamptz', (c) => c.notNull())
      .addUniqueConstraint('intel_items_source_guid_unique', ['source_id', 'guid'])
      .execute();
    await db.schema.createIndex('intel_items_status_idx').on('intel_items').columns(['status', 'fetched_at']).execute();

    await db.schema
      .createTable('advisories')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('key', 'text', (c) => c.notNull().unique())
      .addColumn('ecosystem', 'text', (c) => c.notNull())
      .addColumn('package_name', 'text', (c) => c.notNull())
      .addColumn('package_key', 'text', (c) => c.notNull())
      .addColumn('affected_range', 'text', (c) => c.notNull())
      .addColumn('fixed_version', 'text')
      .addColumn('severity', 'text', (c) => c.notNull())
      .addColumn('cvss_score', 'double precision')
      .addColumn('cve_ids', 'jsonb', (c) => c.notNull())
      .addColumn('title', 'text', (c) => c.notNull())
      .addColumn('summary', 'text', (c) => c.notNull())
      .addColumn('refs', 'jsonb', (c) => c.notNull())
      .addColumn('source', 'text', (c) => c.notNull())
      .addColumn('source_item_id', 'uuid')
      .addColumn('withdrawn', 'boolean', (c) => c.notNull())
      .addColumn('auto_approved', 'boolean', (c) => c.notNull())
      .addColumn('created_by', 'uuid')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('advisories_package_idx').on('advisories').columns(['ecosystem', 'package_key']).execute();
  },
};

migrations['0007_api_tokens'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('api_tokens')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('user_id', 'uuid', (c) => c.notNull().references('users.id').onDelete('cascade'))
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('token_hash', 'text', (c) => c.notNull().unique())
      .addColumn('prefix', 'text', (c) => c.notNull())
      .addColumn('scopes', 'jsonb', (c) => c.notNull())
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .addColumn('last_used_at', 'timestamptz')
      .addColumn('last_used_ip', 'text')
      .addColumn('revoked_at', 'timestamptz')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('api_tokens_user_idx').on('api_tokens').column('user_id').execute();
  },
};

migrations['0008_credentials'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('credentials')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('kind', 'text', (c) => c.notNull())
      .addColumn('system', 'text', (c) => c.notNull())
      .addColumn('owner', 'text', (c) => c.notNull())
      .addColumn('team_id', 'uuid', (c) => c.references('teams.id').onDelete('set null'))
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .addColumn('notes', 'text', (c) => c.notNull())
      .addColumn('notify_emails', 'jsonb', (c) => c.notNull())
      .addColumn('source', 'text', (c) => c.notNull())
      .addColumn('external_id', 'text')
      .addColumn('archived', 'boolean', (c) => c.notNull())
      .addColumn('last_notice_days', 'integer')
      .addColumn('created_by', 'uuid')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('updated_at', 'timestamptz', (c) => c.notNull())
      .addUniqueConstraint('credentials_source_external_unique', ['source', 'external_id'])
      .execute();
    await db.schema.createIndex('credentials_expiry_idx').on('credentials').columns(['archived', 'expires_at']).execute();
  },
};

migrations['0009_saved_views'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('saved_views')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('user_id', 'uuid', (c) => c.notNull().references('users.id').onDelete('cascade'))
      .addColumn('page', 'text', (c) => c.notNull())
      .addColumn('name', 'text', (c) => c.notNull())
      .addColumn('query', 'text', (c) => c.notNull())
      .addColumn('shared', 'boolean', (c) => c.notNull())
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .execute();
    await db.schema.createIndex('saved_views_user_page_idx').on('saved_views').columns(['user_id', 'page']).execute();
  },
};

migrations['0010_invites'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('invites')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('token_hash', 'text', (c) => c.notNull().unique())
      .addColumn('role', 'text', (c) => c.notNull())
      .addColumn('team_ids', 'jsonb', (c) => c.notNull())
      .addColumn('email', 'text')
      .addColumn('max_uses', 'integer', (c) => c.notNull())
      .addColumn('uses', 'integer', (c) => c.notNull())
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .addColumn('note', 'text', (c) => c.notNull())
      .addColumn('created_by', 'uuid', (c) => c.references('users.id').onDelete('set null'))
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('last_used_at', 'timestamptz')
      .addColumn('revoked_at', 'timestamptz')
      .execute();
  },
};

migrations['0011_invite_emails'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    // One optional address becomes a list of addresses, each usable once.
    await db.schema
      .alterTable('invites')
      .addColumn('emails', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .addColumn('used_emails', 'jsonb', (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
      .execute();
    await sql`update invites set emails = jsonb_build_array(lower(email)), used_emails = case when uses > 0 then jsonb_build_array(lower(email)) else '[]'::jsonb end where email is not null`.execute(db);
    await db.schema.alterTable('invites').dropColumn('email').execute();
  },
};

migrations['0012_login_links'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('login_links')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('user_id', 'uuid', (c) => c.notNull().references('users.id').onDelete('cascade'))
      .addColumn('token_hash', 'text', (c) => c.notNull().unique())
      .addColumn('expires_at', 'timestamptz', (c) => c.notNull())
      .addColumn('used_at', 'timestamptz')
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('requested_ip', 'text')
      .execute();
    await db.schema.createIndex('login_links_user_idx').on('login_links').columns(['user_id', 'created_at']).execute();
  },
};

migrations['0013_pr_scans'] = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async up(db: Kysely<any>) {
    await db.schema
      .createTable('pr_scans')
      .addColumn('id', 'uuid', (c) => c.primaryKey())
      .addColumn('repo_id', 'uuid', (c) => c.notNull().references('repositories.id').onDelete('cascade'))
      .addColumn('source_id', 'uuid', (c) => c.notNull().references('sources.id').onDelete('cascade'))
      .addColumn('number', 'integer', (c) => c.notNull())
      .addColumn('title', 'text')
      .addColumn('url', 'text')
      .addColumn('head_sha', 'text')
      .addColumn('head_branch', 'text')
      .addColumn('base_branch', 'text')
      .addColumn('status', 'text', (c) => c.notNull())
      .addColumn('fail_on', 'text', (c) => c.notNull())
      .addColumn('comment', 'boolean', (c) => c.notNull())
      .addColumn('requested_by', 'uuid', (c) => c.references('users.id').onDelete('set null'))
      .addColumn('result', 'jsonb')
      .addColumn('comment_id', 'text')
      .addColumn('comment_url', 'text')
      .addColumn('error', 'text')
      .addColumn('log', 'jsonb', (c) => c.notNull())
      .addColumn('created_at', 'timestamptz', (c) => c.notNull())
      .addColumn('started_at', 'timestamptz')
      .addColumn('finished_at', 'timestamptz')
      .execute();
    await db.schema.createIndex('pr_scans_repo_number_idx').on('pr_scans').columns(['repo_id', 'number', 'created_at']).execute();
    await db.schema.createIndex('pr_scans_repo_created_idx').on('pr_scans').columns(['repo_id', 'created_at']).execute();
  },
};

export const migrationProvider: MigrationProvider = {
  async getMigrations() {
    return migrations;
  },
};
