"""Initial migration - create all tables

Revision ID: 001_initial
Revises:
Create Date: 2026-02-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- servers ---
    op.create_table(
        "servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), unique=True, nullable=False),
        sa.Column("fqdn", sa.String(512), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("os_name", sa.String(128), nullable=True),
        sa.Column("os_version", sa.String(64), nullable=True),
        sa.Column("kernel_version", sa.String(128), nullable=True),
        sa.Column("agent_version", sa.String(32), nullable=True),
        sa.Column("storcli_version", sa.String(32), nullable=True),
        sa.Column("cpu_model", sa.String(256), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("ram_total_gb", sa.Float(), nullable=True),
        sa.Column("uptime_seconds", sa.Integer(), nullable=True),
        sa.Column("last_os_update", sa.String(128), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_report", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("server_info", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("debug_mode", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_servers_hostname", "servers", ["hostname"])
    op.create_index("ix_servers_status", "servers", ["status"])

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(128), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=True),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("email", sa.String(256), nullable=True),
        sa.Column("auth_source", sa.String(16), nullable=False, server_default="local"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("language", sa.String(5), nullable=False, server_default="en"),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("local_admin_expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- settings ---
    op.create_table(
        "settings",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("is_encrypted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("category", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_settings_category", "settings", ["category"])

    # --- agent_packages ---
    op.create_table(
        "agent_packages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version", sa.String(32), unique=True, nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("file_hash_sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("release_notes", sa.Text(), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- alert_rules ---
    op.create_table(
        "alert_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("name_ru", sa.String(256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("description_ru", sa.Text(), nullable=True),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("condition_type", sa.String(64), nullable=False),
        sa.Column("condition_params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="warning"),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("notify_telegram", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default=sa.text("60")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alert_rules_category", "alert_rules", ["category"])

    # --- api_keys --- (depends on servers)
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("servers.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- controllers --- (depends on servers)
    op.create_table(
        "controllers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("controller_id", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(256), nullable=True),
        sa.Column("serial_number", sa.String(128), nullable=True),
        sa.Column("firmware_version", sa.String(64), nullable=True),
        sa.Column("bios_version", sa.String(64), nullable=True),
        sa.Column("driver_version", sa.String(64), nullable=True),
        sa.Column("status", sa.String(64), nullable=True),
        sa.Column("memory_size", sa.String(32), nullable=True),
        sa.Column("memory_correctable_errors", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("memory_uncorrectable_errors", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("roc_temperature", sa.Integer(), nullable=True),
        sa.Column("rebuild_rate", sa.Integer(), nullable=True),
        sa.Column("patrol_read_status", sa.String(64), nullable=True),
        sa.Column("cc_status", sa.String(64), nullable=True),
        sa.Column("alarm_status", sa.String(32), nullable=True),
        sa.Column("raw_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("server_id", "controller_id", name="uq_controller_server"),
    )

    # --- alert_history --- (depends on alert_rules, servers)
    op.create_table(
        "alert_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("servers.id", ondelete="CASCADE"), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notified_telegram", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alert_history_is_resolved", "alert_history", ["is_resolved"])
    op.create_index("ix_alert_history_created_at", "alert_history", ["created_at"])

    # --- audit_log --- (depends on users)
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("username", sa.String(128), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("extra", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])

    # --- bbu_units --- (depends on controllers)
    op.create_table(
        "bbu_units",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("controller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controllers.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("bbu_type", sa.String(32), nullable=True),
        sa.Column("state", sa.String(64), nullable=True),
        sa.Column("voltage", sa.String(32), nullable=True),
        sa.Column("temperature", sa.Integer(), nullable=True),
        sa.Column("learn_cycle_status", sa.String(64), nullable=True),
        sa.Column("next_learn_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("manufacture_date", sa.String(32), nullable=True),
        sa.Column("design_capacity", sa.String(32), nullable=True),
        sa.Column("remaining_capacity", sa.String(32), nullable=True),
        sa.Column("replacement_needed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("raw_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- virtual_drives --- (depends on controllers)
    op.create_table(
        "virtual_drives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("controller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vd_id", sa.Integer(), nullable=False),
        sa.Column("dg_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(256), nullable=True),
        sa.Column("raid_type", sa.String(16), nullable=False),
        sa.Column("state", sa.String(64), nullable=False),
        sa.Column("size", sa.String(32), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("strip_size", sa.String(16), nullable=True),
        sa.Column("number_of_drives", sa.Integer(), nullable=True),
        sa.Column("cache_policy", sa.String(64), nullable=True),
        sa.Column("io_policy", sa.String(32), nullable=True),
        sa.Column("read_policy", sa.String(32), nullable=True),
        sa.Column("disk_cache_policy", sa.String(32), nullable=True),
        sa.Column("consistent", sa.Boolean(), nullable=True),
        sa.Column("access", sa.String(32), nullable=True),
        sa.Column("raw_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("controller_id", "vd_id", name="uq_vd_controller"),
    )
    op.create_index("ix_virtual_drives_state", "virtual_drives", ["state"])

    # --- physical_drives --- (depends on controllers)
    op.create_table(
        "physical_drives",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("controller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("enclosure_id", sa.Integer(), nullable=False),
        sa.Column("slot_number", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("drive_group", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(64), nullable=False),
        sa.Column("size", sa.String(32), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("media_type", sa.String(16), nullable=True),
        sa.Column("interface_type", sa.String(16), nullable=True),
        sa.Column("model", sa.String(256), nullable=True),
        sa.Column("serial_number", sa.String(128), nullable=True),
        sa.Column("firmware_version", sa.String(64), nullable=True),
        sa.Column("manufacturer", sa.String(128), nullable=True),
        sa.Column("sector_size", sa.String(16), nullable=True),
        sa.Column("rotation_speed", sa.String(16), nullable=True),
        sa.Column("temperature", sa.Integer(), nullable=True),
        sa.Column("shield_counter", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("media_error_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("other_error_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("predictive_failure", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("smart_alert", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("smart_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("pd_raw_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("controller_id", "enclosure_id", "slot_number", name="uq_pd_controller"),
    )
    op.create_index("ix_physical_drives_state", "physical_drives", ["state"])
    op.create_index("ix_physical_drives_smart_alert", "physical_drives", ["smart_alert"])

    # --- controller_events --- (depends on controllers)
    op.create_table(
        "controller_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("controller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("controllers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("event_class", sa.String(64), nullable=True),
        sa.Column("event_description", sa.Text(), nullable=True),
        sa.Column("event_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_controller_events_controller_id", "controller_events", ["controller_id"])
    op.create_index("ix_controller_events_event_time", "controller_events", ["event_time"])
    op.create_index("ix_controller_events_severity", "controller_events", ["severity"])

    # --- smart_history --- (depends on physical_drives)
    op.create_table(
        "smart_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("physical_drive_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("physical_drives.id", ondelete="CASCADE"), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("temperature", sa.Integer(), nullable=True),
        sa.Column("media_error_count", sa.Integer(), nullable=True),
        sa.Column("other_error_count", sa.Integer(), nullable=True),
        sa.Column("predictive_failure", sa.Integer(), nullable=True),
        sa.Column("reallocated_sectors", sa.Integer(), nullable=True),
        sa.Column("power_on_hours", sa.Integer(), nullable=True),
        sa.Column("smart_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_index("ix_smart_history_physical_drive_id", "smart_history", ["physical_drive_id"])
    op.create_index("ix_smart_history_recorded_at", "smart_history", ["recorded_at"])


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.drop_table("smart_history")
    op.drop_table("controller_events")
    op.drop_table("physical_drives")
    op.drop_table("virtual_drives")
    op.drop_table("bbu_units")
    op.drop_table("audit_log")
    op.drop_table("alert_history")
    op.drop_table("controllers")
    op.drop_table("api_keys")
    op.drop_table("alert_rules")
    op.drop_table("agent_packages")
    op.drop_table("settings")
    op.drop_table("users")
    op.drop_table("servers")
