#!/usr/bin/env bash
# Run the OpenID Foundation Config, Basic and Dynamic plans against the playground.
# Usage: conformance/run.sh [--keep]
# --keep leaves the containers running, to read the logs at
# https://localhost.emobix.co.uk:8443.
set -euo pipefail

cd "$(dirname "$0")"

USAGE="Usage: conformance/run.sh [--keep]"
SUITE_URL=https://localhost.emobix.co.uk:8443/
STOP_COMMAND="docker compose -f conformance/compose.yaml down --volumes"

keep=false
case $# in
    0) ;;
    1)
        if [ "$1" != "--keep" ]; then
            echo "$USAGE" >&2
            exit 2
        fi
        keep=true
        ;;
    *)
        echo "$USAGE" >&2
        exit 2
        ;;
esac

# The runner files come from the tag of the suite image in compose.yaml.
# The image may also carry a digest: registry/name:tag@sha256:...
SUITE_IMAGE=$(docker compose config --images | grep '^registry.gitlab.com/openid/conformance-suite[:@]' || true)
SUITE_IMAGE=${SUITE_IMAGE%%@*}
case $SUITE_IMAGE in
    registry.gitlab.com/openid/conformance-suite:?*)
        SUITE_TAG=${SUITE_IMAGE##*:}
        ;;
    *)
        echo "compose.yaml has no tagged registry.gitlab.com/openid/conformance-suite image." >&2
        exit 1
        ;;
esac
RAW_URL=https://gitlab.com/openid/conformance-suite/-/raw/$SUITE_TAG/scripts
CACHE=.cache/$SUITE_TAG

# A second run would reuse the containers of the first one, then remove them.
if [ -n "$(docker compose ps --all --quiet)" ]; then
    echo "A conformance stack already exists. Stop it with:" >&2
    echo "$STOP_COMMAND" >&2
    exit 1
fi

# The runner loads the client certificates of this folder. The Config, Basic
# and Dynamic plans need none.
mkdir -p "$CACHE/certs-keys"
for file in run-test-plan.py conformance.py test_plan_parser.py; do
    if [ ! -f "$CACHE/$file" ]; then
        curl --fail --silent --show-error --location --retry 3 --max-time 60 \
            --output "$CACHE/$file.tmp" "$RAW_URL/$file"
        mv "$CACHE/$file.tmp" "$CACHE/$file"
    fi
done

# The suite nginx certificate has no SAN, so the playground cannot fetch
# the suite URLs (jwks_uri, sector_identifier_uri, request_uri). Each run
# makes a new certificate. The playground trusts it with SSL_CERT_FILE.
mkdir -p tls
if ! output=$(openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=localhost.emobix.co.uk" \
    -addext "subjectAltName=DNS:localhost.emobix.co.uk" \
    -keyout tls/suite.key -out tls/suite.crt 2>&1); then
    printf '%s\n' "$output" >&2
    exit 1
fi

# The runner does not create its export folder.
rm -rf results
mkdir results

stop() {
    local status=$?
    trap - EXIT INT TERM
    if [ "$status" -ne 0 ]; then
        docker compose logs --no-color app caddy server nginx > results/compose.log 2>&1 || true
        echo "The container logs are in conformance/results/compose.log." >&2
    fi
    if [ "$keep" = true ]; then
        echo "The containers are still running. Stop them with:"
        echo "$STOP_COMMAND"
    else
        docker compose down --volumes
    fi
    exit "$status"
}

trap stop EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker compose up --build --detach --wait

echo "Waiting for the suite..."
tries=0
until curl --fail --silent --insecure --max-time 5 --output /dev/null "$SUITE_URL"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 90 ]; then
        echo "The suite did not start." >&2
        exit 1
    fi
    sleep 2
done

CONFORMANCE_SERVER=$SUITE_URL \
CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/ \
CONFORMANCE_DEV_MODE=1 \
uv run --only-group conformance python "$CACHE/run-test-plan.py" \
    --expected-failures-file expected-failures.json \
    --expected-skips-file expected-skips.json \
    --export-dir results \
    --verbose \
    "oidcc-config-certification-test-plan" config.json \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" config.json \
    "oidcc-dynamic-certification-test-plan[response_type=code]" dynamic.json
