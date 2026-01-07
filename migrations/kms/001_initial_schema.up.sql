-- migrations/kms/001_initial_schema.up.sql
-- KMS 数据库初始化脚本

-- 启用 UUID 扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 主密钥表
CREATE TABLE IF NOT EXISTS master_keys (
                                           id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    usage VARCHAR(32) NOT NULL,
    encrypted_key_material JSONB NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    version INT NOT NULL DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    rotation_schedule INTERVAL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,

    CONSTRAINT check_state CHECK (state IN ('ENABLED', 'DISABLED', 'PENDING_DELETION', 'DELETED')),
    CONSTRAINT check_algorithm CHECK (algorithm IN ('RSA_2048', 'RSA_4096', 'AES_256_GCM', 'AES_128_GCM', 'ECDSA_P256', 'ECDSA_P384')),
    CONSTRAINT check_usage CHECK (usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY'))
    );

-- 索引
CREATE INDEX idx_master_keys_key_id ON master_keys(key_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_master_keys_tenant_state ON master_keys(tenant_id, state) WHERE deleted_at IS NULL;
CREATE INDEX idx_master_keys_created_at ON master_keys(created_at DESC);

-- 密钥版本表（支持密钥轮换）
CREATE TABLE IF NOT EXISTS key_versions (
                                            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    master_key_id UUID NOT NULL REFERENCES master_keys(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    encrypted_key_material JSONB NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'ENABLED',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deprecated_at TIMESTAMP,

    UNIQUE(master_key_id, version_number),
    CONSTRAINT check_version_state CHECK (state IN ('ENABLED', 'DISABLED', 'DEPRECATED'))
    );

CREATE INDEX idx_key_versions_master_key ON key_versions(master_key_id, version_number DESC);

-- 密钥操作审计日志表（分区表，按时间分区）
CREATE TABLE IF NOT EXISTS key_operations (
                                              id BIGSERIAL,
                                              key_id VARCHAR(64) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    requestor VARCHAR(255),
    ip_address INET,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp);

-- 创建初始分区（当前月份）
CREATE TABLE IF NOT EXISTS key_operations_default PARTITION OF key_operations DEFAULT;

-- 索引
CREATE INDEX idx_key_operations_key_id ON key_operations(key_id, timestamp DESC);
CREATE INDEX idx_key_operations_timestamp ON key_operations(timestamp DESC);
CREATE INDEX idx_key_operations_requestor ON key_operations(requestor, timestamp DESC);

-- 密钥访问策略表
CREATE TABLE IF NOT EXISTS key_policies (
                                            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(64) NOT NULL,
    principal VARCHAR(255) NOT NULL,
    actions TEXT[] NOT NULL,
    effect VARCHAR(10) NOT NULL DEFAULT 'ALLOW',
    conditions JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(key_id, principal),
    CONSTRAINT check_effect CHECK (effect IN ('ALLOW', 'DENY'))
    );

CREATE INDEX idx_key_policies_key_id ON key_policies(key_id);
CREATE INDEX idx_key_policies_principal ON key_policies(principal);

-- 密钥别名表
CREATE TABLE IF NOT EXISTS key_aliases (
                                           id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alias_name VARCHAR(255) UNIQUE NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (key_id) REFERENCES master_keys(key_id) ON DELETE CASCADE
    );

CREATE INDEX idx_key_aliases_alias_name ON key_aliases(alias_name);
CREATE INDEX idx_key_aliases_key_id ON key_aliases(key_id);

-- 更新 updated_at 的触发器函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 为 master_keys 表添加触发器
CREATE TRIGGER update_master_keys_updated_at
    BEFORE UPDATE ON master_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 注释
COMMENT ON TABLE master_keys IS '主密钥表，存储加密后的密钥材料';
COMMENT ON COLUMN master_keys.key_id IS '对外暴露的密钥标识符';
COMMENT ON COLUMN master_keys.encrypted_key_material IS '使用 Root Key 加密后的密钥材料';
COMMENT ON COLUMN master_keys.rotation_schedule IS '密钥自动轮换周期';

COMMENT ON TABLE key_versions IS '密钥版本表，支持密钥轮换历史';
COMMENT ON TABLE key_operations IS '密钥操作审计日志，记录所有密钥使用情况';
COMMENT ON TABLE key_policies IS '密钥访问策略，控制谁可以使用哪些密钥';
COMMENT ON TABLE key_aliases IS '密钥别名，方便管理和引用密钥';