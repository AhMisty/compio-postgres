#!/usr/bin/env bash
set -euo pipefail

mode=${1-}
if ! { (( $# == 0 )) || { [[ $mode == --tls-only ]] && (( $# == 1 )); } ||
       { [[ $mode == --native ]] && (( $# == 2 )); }; }; then
    printf '用法：bash scripts/test-postgres.sh [--tls-only | --native PORT]\n' >&2
    exit 2
fi
if [[ $mode == --native ]]; then
    if [[ ! $2 =~ ^[0-9]{1,5}$ ]] || (( 10#$2 < 1 || 10#$2 > 65535 )); then
        printf '原生 PostgreSQL 所用端口必须在 1 到 65535 之间\n' >&2
        exit 2
    fi
    if (( EUID == 0 )); then
        printf '请用普通用户启动原生 PostgreSQL 测试夹具\n' >&2
        exit 2
    fi
    if [[ $(postgres --version) != "postgres (PostgreSQL) 19."* ]]; then
        printf '请将 PostgreSQL 19 的 bin 目录加入 PATH\n' >&2
        exit 2
    fi
fi

umask 077
fixture_root=$(cd -- "${TMPDIR:-/tmp}" && pwd -P)
fixture=$(mktemp -d "$fixture_root/cpg.XXXXXXXX")
if [[ $fixture != "$fixture_root"/cpg.???????? ]]; then
    printf '测试夹具路径无效：%s\n' "$fixture" >&2
    exit 1
fi
cid_file="$fixture/container.id"

cleanup() {
    if [[ $mode == --native && -f "$fixture/data/postmaster.pid" ]] &&
        ! pg_ctl -D "$fixture/data" -m immediate -w -t 30 stop >/dev/null; then
        printf '无法停止 PostgreSQL 测试实例，保留夹具 %s\n' "$fixture" >&2
        exit 1
    fi
    if [[ -s "$cid_file" ]]; then
        local id remaining
        id=$(<"$cid_file")
        if ! docker stop "$id" >/dev/null 2>&1; then
            if ! remaining=$(docker ps --all --quiet --filter "id=$id") || [[ -n "$remaining" ]]; then
                printf '无法停止 PostgreSQL 测试容器 %s，保留夹具 %s\n' "$id" "$fixture" >&2
                exit 1
            fi
        fi
    fi
    rm -r -- "$fixture"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

issue_certificate() {
    local destination=$1 name=$2 usage=$3 serial=$4
    local config="$destination/leaf.cnf"
    cat >"$config" <<EOF
[req]
distinguished_name = subject
prompt = no
[subject]
CN = $name
[leaf]
basicConstraints = CA:FALSE
extendedKeyUsage = $usage
subjectAltName = DNS:$name
EOF
    openssl ecparam -name prime256v1 -genkey -noout -out "$destination/leaf.key"
    openssl req -new -sha256 -key "$destination/leaf.key" -config "$config" \
        -out "$destination/leaf.csr"
    openssl x509 -req -sha256 -days 7 -CA "$fixture/server/ca.crt" -CAkey "$fixture/ca.key" \
        -set_serial "$serial" -in "$destination/leaf.csr" -extfile "$config" \
        -extensions leaf -out "$destination/leaf.crt"
}

server_name=localhost
mkdir "$fixture/server"
cat >"$fixture/ca.cnf" <<'EOF'
[req]
distinguished_name = subject
prompt = no
[subject]
CN = cpg-test-ca
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$fixture/ca.key"
openssl req -new -x509 -sha256 -days 7 -config "$fixture/ca.cnf" -extensions ca \
    -key "$fixture/ca.key" -out "$fixture/server/ca.crt"
issue_certificate "$fixture/server" "$server_name" serverAuth 1

test_fixture=$fixture
# Git Bash 的 POSIX 路径须先转换，原生 Windows 测试进程用转换后的路径读取证书。
case $OSTYPE in
    cygwin*|msys*) test_fixture=$(cygpath -m "$fixture") ;;
esac
export CPG_TLS_SERVER_NAME="$server_name"
export CPG_TLS_CA_PEM="$test_fixture/server/ca.crt"
export CPG_TLS_SERVER_CERT_PEM="$test_fixture/server/leaf.crt"
export CPG_TLS_SERVER_KEY_PEM="$test_fixture/server/leaf.key"

if [[ $mode == --tls-only ]]; then
    cargo test --locked --all-features --test tls -- --ignored --exact \
        direct_tls_without_postgresql_alpn_is_rejected \
        only_postgresql_frames_crossing_authenticated_records_are_copied \
        copy_out_terminals_avoid_staging_payloads_across_tls_records
    exit
fi

export CPG_HOST=127.0.0.1 CPG_USER=cpg_fixture CPG_DATABASE=postgres
CPG_PASSWORD=$(openssl rand -hex 24)
export CPG_PASSWORD
mkdir "$fixture/client"
issue_certificate "$fixture/client" "$CPG_USER" clientAuth 2
export CPG_TLS_CLIENT_CERT_PEM="$fixture/client/leaf.crt"
export CPG_TLS_CLIENT_KEY_PEM="$fixture/client/leaf.key"

write_tls_config() {
    local directory=$1
    cat <<EOF
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_cert_file = '$directory/leaf.crt'
ssl_key_file = '$directory/leaf.key'
ssl_ca_file = '$directory/ca.crt'
EOF
}

if [[ $mode == --native ]]; then
    export CPG_PORT=$((10#$2))
    export CPG_UNIX_PATH="$fixture/socket/.s.PGSQL.$CPG_PORT"
    printf '%s\n' "$CPG_PASSWORD" >"$fixture/password"
    initdb -D "$fixture/data" --username="$CPG_USER" --pwfile="$fixture/password" \
        --auth=scram-sha-256 --encoding=UTF8 --locale=C --no-instructions >/dev/null
    mkdir "$fixture/socket"
    socket_dir=${fixture//\\/\\\\}/socket
    socket_dir=${socket_dir//\'/\'\'}
    cat >>"$fixture/data/postgresql.conf" <<EOF
listen_addresses = '$CPG_HOST'
port = $CPG_PORT
unix_socket_directories = '$socket_dir'
EOF
    write_tls_config ../server >>"$fixture/data/postgresql.conf"
    if ! pg_ctl -D "$fixture/data" -l "$fixture/postgres.log" -w -t 60 start >/dev/null; then
        tail -n 30 "$fixture/postgres.log" >&2
        exit 1
    fi
else
    export CPG_UNIX_PATH="$fixture/socket/.s.PGSQL.5432"
    # 套接字由容器内的 postgres 用户创建，宿主仅允许当前用户访问夹具的父目录。
    mkdir -m 1777 "$fixture/socket"

    POSTGRES_USER="$CPG_USER" POSTGRES_PASSWORD="$CPG_PASSWORD" docker run \
        --detach --rm --cidfile "$cid_file" --publish 127.0.0.1::5432 \
        --env POSTGRES_USER --env POSTGRES_PASSWORD \
        --env POSTGRES_INITDB_ARGS=--auth=scram-sha-256 \
        --env POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
        --mount "type=bind,source=$fixture/socket,target=/socket" \
        postgres:19.0 postgres -c unix_socket_directories=/var/run/postgresql,/socket >/dev/null
    container=$(<"$cid_file")

    for attempt in {1..60}; do
        if docker exec "$container" pg_isready -q -h "$CPG_HOST" -U "$CPG_USER" -d "$CPG_DATABASE"; then
            break
        fi
        if [[ "$attempt" == 60 ]]; then
            docker logs --tail 60 "$container"
            exit 1
        fi
        sleep 1
    done

    # 默认入口完成数据库初始化后，证书由 postgres 写入自己的数据目录。
    docker exec --user postgres "$container" sh -eu -c 'umask 077; mkdir "$PGDATA/cpg-tls"'
    for file in ca.crt leaf.crt leaf.key; do
        docker exec -i --user postgres "$container" sh -eu -c '
            umask 077
            cat >"$PGDATA/cpg-tls/$1"
        ' sh "$file" <"$fixture/server/$file"
    done
    write_tls_config cpg-tls | docker exec -i --user postgres "$container" sh -eu -c '
        cat >>"$PGDATA/postgresql.conf"
        exec pg_ctl -D "$PGDATA" reload
    ' >/dev/null

    for attempt in {1..60}; do
        if docker exec --user postgres "$container" sh -eu -c '
            PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=require PGCONNECT_TIMEOUT=2 exec psql -X -w -qAt \
                -h "$1" -U "$POSTGRES_USER" -d "$2" -c "SELECT 1"
        ' sh "$CPG_HOST" "$CPG_DATABASE" >/dev/null 2>&1; then
            break
        fi
        if [[ "$attempt" == 60 ]]; then
            docker logs --tail 60 "$container"
            exit 1
        fi
        sleep 1
    done

    endpoint=$(docker port "$container" 5432/tcp)
    export CPG_PORT="${endpoint##*:}"
fi

cargo test --locked --all-features -- --ignored --test-threads=1
