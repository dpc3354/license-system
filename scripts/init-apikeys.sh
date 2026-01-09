#!/bin/bash
# API Key 初始化脚本
# 用于在数据库中添加默认的测试 API Key

set -e

# 数据库连接信息
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-kms}"
DB_PASSWORD="${DB_PASSWORD:-kms_password}"
DB_NAME="${DB_NAME:-kms}"

echo "🔑 初始化 API Keys..."
echo ""

# 定义 API Keys（这些是示例密钥，生产环境应该使用安全生成的密钥）
declare -A API_KEYS
API_KEYS["development"]="kms_testkey_123456789abcdef:开发测试用"
API_KEYS["license-server"]="kms_4f8d9e2a1b3c5d6e7f8a9b0c1d2e3f4a:License Server 服务"
API_KEYS["monitoring-service"]="kms_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:监控服务"

# 函数：计算 SHA256 哈希
hash_api_key() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

# 函数：添加 API Key
add_api_key() {
    local name=$1
    local api_key=$2
    local description=$3

    # shellcheck disable=SC2155
    local key_hash=$(hash_api_key "$api_key")

    echo "添加 API Key: $name"
    echo "  Key Hash: $key_hash"

    echo "INSERT INTO api_keys (name, key_hash, description) VALUES ('$name', '$key_hash', '$description') ON CONFLICT (name) DO UPDATE SET key_hash = EXCLUDED.key_hash, description = EXCLUDED.description RETURNING *;" | \
    docker exec -i postgres-dev env PGPASSWORD=$DB_PASSWORD psql \
          -h localhost -p 5432 -U $DB_USER -d $DB_NAME

    EXIT_CODE=$?

    echo "  输出: $OUTPUT"
    echo "  退出码: $EXIT_CODE"

    if [ $EXIT_CODE -eq 0 ]; then
        echo "  ✅ 成功"
    else
        echo "  ❌ 失败"
    fi
    echo ""
}

# 检查数据库连接
echo "检查数据库连接..."
docker exec postgres-dev env PGPASSWORD=$DB_PASSWORD psql -h localhost -p 5432 -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ 无法连接到数据库"
    echo "请检查数据库是否运行，以及连接参数是否正确"
    exit 1
fi
echo "✅ 数据库连接成功"
echo ""

# 检查 api_keys 表是否存在
echo "检查 api_keys 表..."
docker exec postgres-dev env PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT 1 FROM api_keys LIMIT 1;" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ api_keys 表不存在"
    echo "请先运行数据库迁移: make migrate-up"
    exit 1
fi
echo "✅ api_keys 表存在"
echo ""

# 添加 API Keys
for name in "${!API_KEYS[@]}"; do
    IFS=':' read -r api_key description <<< "${API_KEYS[$name]}"
    add_api_key "$name" "$api_key" "$description"
done

# 显示当前的 API Keys
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "当前数据库中的 API Keys:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker exec postgres-dev env PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "
SELECT
    name,
    CASE WHEN enabled THEN '✅' ELSE '❌' END as enabled,
    description,
    created_at::date as created,
    CASE
        WHEN last_used_at IS NULL THEN '从未使用'
        ELSE last_used_at::text
    END as last_used
FROM api_keys
ORDER BY created_at DESC;
"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 API Keys 初始化完成！"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "测试 API Key:"
for name in "${!API_KEYS[@]}"; do
    IFS=':' read -r api_key description <<< "${API_KEYS[$name]}"
    echo "  $name: $api_key"
done
echo ""
echo "使用示例:"
echo "  curl -H \"Authorization: Bearer kms_testkey_123456789abcdef\" \\"
echo "       http://localhost:8080/api/v1/keys"