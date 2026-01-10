package keystore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dpc3354/license-system/internal/kms/models"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var (
	ErrKeyNotFound     = fmt.Errorf("key not found")
	ErrKeyExists       = fmt.Errorf("key already exists")
	ErrInvalidKeyState = fmt.Errorf("invalid key state")
)

// KeyStore 密钥存储接口
type KeyStore interface {
	// SaveKey 保存主密钥
	SaveKey(ctx context.Context, key *models.MasterKey) error

	// GetKey 根据 KeyID 获取密钥
	GetKey(ctx context.Context, keyID string) (*models.MasterKey, error)

	// GetKeyByID 根据内部 ID 获取密钥
	GetKeyByID(ctx context.Context, id string) (*models.MasterKey, error)

	// ListKeys 列出租户的所有密钥
	ListKeys(ctx context.Context, tenantID string, state models.KeyState) ([]*models.MasterKey, error)

	// UpdateKeyState 更新密钥状态
	UpdateKeyState(ctx context.Context, keyID string, newState models.KeyState) error

	// DeleteKey 软删除密钥
	DeleteKey(ctx context.Context, keyID string) error

	// SaveKeyVersion 保存密钥版本
	SaveKeyVersion(ctx context.Context, version *models.KeyVersion) error

	// GetLatestKeyVersion 获取最新的密钥版本
	GetLatestKeyVersion(ctx context.Context, masterKeyID string) (*models.KeyVersion, error)

	// UpdateKeyVersionState 更新密钥版本状态
	UpdateKeyVersionState(ctx context.Context, versionID string, newState models.KeyState) error

	// LogOperation 记录密钥操作日志
	LogOperation(ctx context.Context, op *models.KeyOperation) error

	// SaveKeyPolicy 保存密钥访问策略
	SaveKeyPolicy(ctx context.Context, policy *models.KeyPolicy) error

	// GetKeyPolicy 获取密钥的访问策略
	GetKeyPolicy(ctx context.Context, keyID, principal string) (*models.KeyPolicy, error)
}

// PostgreSQLKeyStore PostgreSQL 实现
type PostgreSQLKeyStore struct {
	db *sqlx.DB
}

// NewPostgreSQLKeyStore 创建 PostgreSQL 密钥存储
func NewPostgreSQLKeyStore(db *sqlx.DB) *PostgreSQLKeyStore {
	return &PostgreSQLKeyStore{db: db}
}

// SaveKey 保存主密钥
func (s *PostgreSQLKeyStore) SaveKey(ctx context.Context, key *models.MasterKey) error {
	query := `
		INSERT INTO master_keys (
			id, key_id, tenant_id, algorithm, usage,
			encrypted_key_material, state, version, metadata,
			rotation_schedule, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (id) DO UPDATE SET
			encrypted_key_material = EXCLUDED.encrypted_key_material,
			state = EXCLUDED.state,
			version = EXCLUDED.version,
			metadata = EXCLUDED.metadata,
			rotation_schedule = EXCLUDED.rotation_schedule,
			updated_at = EXCLUDED.updated_at
	`

	_, err := s.db.ExecContext(ctx, query,
		key.ID,
		key.KeyID,
		key.TenantID,
		key.Algorithm,
		key.Usage,
		key.EncryptedMaterial,
		key.State,
		key.Version,
		key.Metadata,
		key.RotationSchedule,
		key.CreatedAt,
		key.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("save key: %w", err)
	}

	return nil
}

// GetKey 根据 KeyID 获取密钥
func (s *PostgreSQLKeyStore) GetKey(ctx context.Context, keyID string) (*models.MasterKey, error) {
	var key models.MasterKey

	query := `
		SELECT 
			id, key_id, tenant_id, algorithm, usage,
			encrypted_key_material, state, version, metadata,
			rotation_schedule, created_at, updated_at, deleted_at
		FROM master_keys
		WHERE key_id = $1 AND deleted_at IS NULL
	`

	err := s.db.GetContext(ctx, &key, query, keyID)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	return &key, nil
}

// GetKeyByID 根据内部 ID 获取密钥
func (s *PostgreSQLKeyStore) GetKeyByID(ctx context.Context, id string) (*models.MasterKey, error) {
	var key models.MasterKey

	query := `
		SELECT 
			id, key_id, tenant_id, algorithm, usage,
			encrypted_key_material, state, version, metadata,
			rotation_schedule, created_at, updated_at, deleted_at
		FROM master_keys
		WHERE id = $1 AND deleted_at IS NULL
	`

	err := s.db.GetContext(ctx, &key, query, id)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get key by id: %w", err)
	}

	return &key, nil
}

// ListKeys 列出租户的所有密钥
func (s *PostgreSQLKeyStore) ListKeys(ctx context.Context, tenantID string, state models.KeyState) ([]*models.MasterKey, error) {
	var keys []*models.MasterKey

	query := `
		SELECT 
			id, key_id, tenant_id, algorithm, usage,
			encrypted_key_material, state, version, metadata,
			rotation_schedule, created_at, updated_at, deleted_at
		FROM master_keys
		WHERE tenant_id = $1 AND state = $2 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	err := s.db.SelectContext(ctx, &keys, query, tenantID, state)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	return keys, nil
}

// UpdateKeyState 更新密钥状态
func (s *PostgreSQLKeyStore) UpdateKeyState(ctx context.Context, keyID string, newState models.KeyState) error {
	query := `
		UPDATE master_keys
		SET state = $1, updated_at = $2
		WHERE key_id = $3 AND deleted_at IS NULL
	`

	result, err := s.db.ExecContext(ctx, query, newState, time.Now(), keyID)
	if err != nil {
		return fmt.Errorf("update key state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrKeyNotFound
	}

	return nil
}

// DeleteKey 软删除密钥
func (s *PostgreSQLKeyStore) DeleteKey(ctx context.Context, keyID string) error {
	query := `
		UPDATE master_keys
		SET deleted_at = $1, state = $2, updated_at = $1
		WHERE key_id = $3 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := s.db.ExecContext(ctx, query, now, models.KeyStateDeleted, keyID)
	if err != nil {
		return fmt.Errorf("delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrKeyNotFound
	}

	return nil
}

// SaveKeyVersion 保存密钥版本
func (s *PostgreSQLKeyStore) SaveKeyVersion(ctx context.Context, version *models.KeyVersion) error {
	query := `
		INSERT INTO key_versions (
			id, master_key_id, version_number, encrypted_key_material,
			state, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)
	`

	_, err := s.db.ExecContext(ctx, query,
		version.ID,
		version.MasterKeyID,
		version.VersionNumber,
		version.EncryptedMaterial,
		version.State,
		version.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("save key version: %w", err)
	}

	return nil
}

// GetLatestKeyVersion 获取最新的密钥版本
func (s *PostgreSQLKeyStore) GetLatestKeyVersion(ctx context.Context, masterKeyID string) (*models.KeyVersion, error) {
	var version models.KeyVersion

	query := `
		SELECT 
			id, master_key_id, version_number, encrypted_key_material,
			state, created_at, deprecated_at
		FROM key_versions
		WHERE master_key_id = $1 AND state = $2
		ORDER BY version_number DESC
		LIMIT 1
	`

	err := s.db.GetContext(ctx, &version, query, masterKeyID, models.KeyStateEnabled)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get latest key version: %w", err)
	}

	return &version, nil
}

// UpdateKeyVersionState 更新密钥版本状态
func (s *PostgreSQLKeyStore) UpdateKeyVersionState(ctx context.Context, versionID string, newState models.KeyState) error {
	var query string
	var args []interface{}

	if newState == models.KeyStateDeprecated {
		// 如果是 DEPRECATED，同时更新 deprecated_at
		query = `
			UPDATE key_versions
			SET state = $1,
			    deprecated_at = COALESCE(deprecated_at, NOW())
			WHERE id = $2
		`
		args = []interface{}{newState, versionID}
	} else {
		// 其他状态，只更新 state
		query = `
			UPDATE key_versions
			SET state = $1
			WHERE id = $2
		`
		args = []interface{}{newState, versionID}
	}

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update key version state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrKeyNotFound
	}

	return nil
}

// LogOperation 记录密钥操作日志
func (s *PostgreSQLKeyStore) LogOperation(ctx context.Context, op *models.KeyOperation) error {
	query := `
		INSERT INTO key_operations (
			key_id, operation, requestor, ip_address,
			success, error_message, timestamp
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
	`

	// 处理 IP 地址：空字符串转为 NULL
	var ipAddress interface{}
	if op.IPAddress != "" {
		ipAddress = op.IPAddress
	} else {
		ipAddress = nil // PostgreSQL 的 INET 类型不接受空字符串，必须用 NULL
	}
	_, err := s.db.ExecContext(ctx, query,
		op.KeyID,
		op.Operation,
		op.Requestor,
		ipAddress,
		op.Success,
		op.ErrorMessage,
		op.Timestamp,
	)

	if err != nil {
		// 日志记录失败不应该影响主流程，仅记录错误
		return fmt.Errorf("log operation: %w", err)
	}

	return nil
}

// SaveKeyPolicy 保存密钥访问策略
func (s *PostgreSQLKeyStore) SaveKeyPolicy(ctx context.Context, policy *models.KeyPolicy) error {
	// 将 []string 转换为 PostgreSQL array
	query := `
		INSERT INTO key_policies (
			id, key_id, principal, actions, effect, conditions, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (key_id, principal) 
		DO UPDATE SET 
			actions = EXCLUDED.actions,
			effect = EXCLUDED.effect,
			conditions = EXCLUDED.conditions
	`

	_, err := s.db.ExecContext(ctx, query,
		uuid.New().String(),
		policy.KeyID,
		policy.Principal,
		policy.Actions, // sqlx 会自动处理 []string 到 PostgreSQL array 的转换
		policy.Effect,
		policy.Conditions,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("save key policy: %w", err)
	}

	return nil
}

// GetKeyPolicy 获取密钥的访问策略
func (s *PostgreSQLKeyStore) GetKeyPolicy(ctx context.Context, keyID, principal string) (*models.KeyPolicy, error) {
	var policy models.KeyPolicy

	query := `
		SELECT 
			id, key_id, principal, actions, effect, conditions, created_at
		FROM key_policies
		WHERE key_id = $1 AND principal = $2
	`

	err := s.db.GetContext(ctx, &policy, query, keyID, principal)
	if err == sql.ErrNoRows {
		return nil, nil // 没有策略不是错误
	}
	if err != nil {
		return nil, fmt.Errorf("get key policy: %w", err)
	}

	return &policy, nil
}
