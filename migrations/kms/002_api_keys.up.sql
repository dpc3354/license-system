-- API Keys 表
CREATE TABLE IF NOT EXISTS api_keys (
                                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 哈希值
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_by VARCHAR(255),

    CONSTRAINT check_name_not_empty CHECK (length(name) > 0)
    );

-- 索引
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_enabled ON api_keys(enabled);
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- 注释
COMMENT ON TABLE api_keys IS 'API 密钥表，用于认证和审计';
COMMENT ON COLUMN api_keys.name IS 'API Key 名称（如 license-server, monitoring）';
COMMENT ON COLUMN api_keys.key_hash IS 'API Key 的 SHA256 哈希值';
COMMENT ON COLUMN api_keys.description IS 'API Key 用途描述';
COMMENT ON COLUMN api_keys.enabled IS '是否启用';
COMMENT ON COLUMN api_keys.expires_at IS '过期时间（NULL 表示永不过期）';
COMMENT ON COLUMN api_keys.last_used_at IS '最后使用时间';