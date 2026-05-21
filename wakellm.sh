#!/usr/bin/env bash
# wakellm.sh — Manage wakellm-security Cloud Run Job deployments and executions
#
# Usage:
#   ./wakellm.sh --deploy [--dev|--prod]   Build, scan, and deploy the job image
#   ./wakellm.sh --run    [--dev|--prod]   Execute the deployed job
#
# Flags:
#   --deploy         Build image via Cloud Build, scan with Trivy, deploy Cloud Run Job
#   --run            Trigger a job execution (gcloud run jobs execute)
#   --dev            Target dev job (deploy creates it if missing)
#   --prod           Target prod job (default; deploy update-only)
#
# Environment overrides (optional):
#   SKIP_SCAN=1                        Bypass Trivy scan during --deploy
#   TAG=<git-sha>                      Override the image tag (default: git short SHA)
#   JOB_NAME=<name>                    Override resolved job name
#   SECURITY_MAX_TRIAGE_ITEMS=<n>      Items fed to LLM for triage (default: 40)
#   SECURITY_MAX_ALERT_THREATS=<n>     Threats in final output (default: 10)
#
# Prerequisites:
#   gcloud auth login
#   .env file with required variables (see .env.example)
#   APIs enabled: cloudbuild.googleapis.com, run.googleapis.com, artifactregistry.googleapis.com
#   trivy installed — https://aquasecurity.github.io/trivy (or docker as fallback)
#
set -euo pipefail

# ── Parse arguments ────────────────────────────────────────────────────────────
ACTION=""
DEV_FLAG=0
PROD_FLAG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy)
      ACTION="deploy"
      shift
      ;;
    --run)
      ACTION="run"
      shift
      ;;
    --dev)
      DEV_FLAG=1
      shift
      ;;
    --prod)
      PROD_FLAG=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./wakellm.sh --deploy [--dev|--prod]
       ./wakellm.sh --run    [--dev|--prod]

Actions:
  --deploy   Build image, Trivy scan, deploy Cloud Run Job
  --run      Execute the Cloud Run Job (securityDigest command)

Environments:
  --dev      Target dev job (--deploy creates it if missing)
  --prod     Target prod job (default; --deploy is update-only)

Examples:
  ./wakellm.sh --deploy --dev
  ./wakellm.sh --deploy --prod
  ./wakellm.sh --run --dev
  ./wakellm.sh --run
EOF
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument '$1'. Run with --help for usage." >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ACTION" ]]; then
  echo "ERROR: Specify an action: --deploy or --run" >&2
  echo "Run ./wakellm.sh --help for usage." >&2
  exit 1
fi

if [[ "$DEV_FLAG" -eq 1 && "$PROD_FLAG" -eq 1 ]]; then
  echo "ERROR: Use only one of --dev or --prod." >&2
  exit 1
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  echo "ERROR: .env file not found. Copy .env.example to .env and fill in required values." >&2
  exit 1
fi

# shellcheck disable=SC1091
set +o nounset
source .env
set -o nounset

# ── Validate required variables ───────────────────────────────────────────────
REQUIRED_VARS=(PROJECT REGION PROD_JOB_NAME DEV_JOB_NAME)
if [[ "$ACTION" == "deploy" ]]; then
  REQUIRED_VARS+=(REPO IMAGE_NAME SERVICE_ACCOUNT)
fi

for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: Required variable '$var' not set in .env" >&2
    exit 1
  fi
done

# ── Resolve environment and job name ──────────────────────────────────────────
ENVIRONMENT="${ENVIRONMENT:-prod}"
if [[ "$DEV_FLAG" -eq 1 ]]; then
  ENVIRONMENT="dev"
elif [[ "$PROD_FLAG" -eq 1 ]]; then
  ENVIRONMENT="prod"
fi

if [[ -n "${JOB_NAME:-}" ]]; then
  TARGET_JOB_NAME="$JOB_NAME"
else
  case "$ENVIRONMENT" in
    prod) TARGET_JOB_NAME="$PROD_JOB_NAME" ;;
    dev)  TARGET_JOB_NAME="$DEV_JOB_NAME"  ;;
    *)
      echo "ERROR: ENVIRONMENT must be 'prod' or 'dev' (got '$ENVIRONMENT')." >&2
      exit 1
      ;;
  esac
fi

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: run
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$ACTION" == "run" ]]; then
  echo ""
  echo "════════════════════════════════════════"
  echo "  wakellm-security Job Runner"
  echo "  Environment : $ENVIRONMENT"
  echo "  Project     : $PROJECT"
  echo "  Region      : $REGION"
  echo "  Job         : $TARGET_JOB_NAME"
  echo "════════════════════════════════════════"
  echo ""
  echo "▶ Executing: gcloud run jobs execute $TARGET_JOB_NAME --args='securityDigest'"
  echo ""

  gcloud run jobs execute "$TARGET_JOB_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --wait \
    --args="securityDigest"

  echo ""
  echo "✓ Execution complete."
  exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# ACTION: deploy
# ══════════════════════════════════════════════════════════════════════════════
SKIP_SCAN="${SKIP_SCAN:-0}"
TRIVY_SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
IMAGE="$REGION-docker.pkg.dev/$PROJECT/$REPO/$IMAGE_NAME"
TAG="${TAG:-$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
FULL_IMAGE="$IMAGE:$TAG"
LATEST_IMAGE="$IMAGE:latest"

NODE_ENV_VALUE="${NODE_ENV:-$([[ "$ENVIRONMENT" == "dev" ]] && echo development || echo production)}"
ENV_VARS_CSV="NODE_ENV=$NODE_ENV_VALUE"
[[ -n "${SECURITY_MAX_TRIAGE_ITEMS:-}" ]]  && ENV_VARS_CSV+=",SECURITY_MAX_TRIAGE_ITEMS=$SECURITY_MAX_TRIAGE_ITEMS"
[[ -n "${SECURITY_MAX_ALERT_THREATS:-}" ]] && ENV_VARS_CSV+=",SECURITY_MAX_ALERT_THREATS=$SECURITY_MAX_ALERT_THREATS"

echo ""
echo "════════════════════════════════════════"
echo "  wakellm-security Deploy"
echo "  Environment : $ENVIRONMENT"
echo "  Project     : $PROJECT"
echo "  Region      : $REGION"
echo "  Image       : $FULL_IMAGE"
echo "  Job         : $TARGET_JOB_NAME"
echo "════════════════════════════════════════"

# ── 1. Build and push via Cloud Build ─────────────────────────────────────────
echo ""
echo "▶ Submitting Cloud Build..."
gcloud builds submit \
  --project="$PROJECT" \
  --tag="$FULL_IMAGE" \
  .

echo ""
echo "▶ Tagging :latest..."
gcloud artifacts docker tags add \
  --project="$PROJECT" \
  "$FULL_IMAGE" \
  "$LATEST_IMAGE"

# ── 2. Trivy vulnerability scan ───────────────────────────────────────────────
if [[ "$SKIP_SCAN" == "1" ]]; then
  echo ""
  echo "⚠ Trivy scan skipped (SKIP_SCAN=1)."
else
  echo ""
  echo "▶ Scanning image with Trivy (severity: $TRIVY_SEVERITY)..."
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

  if command -v trivy &>/dev/null; then
    trivy image \
      --exit-code 1 \
      --severity "$TRIVY_SEVERITY" \
      --no-progress \
      --ignore-unfixed \
      "$FULL_IMAGE"
  elif command -v docker &>/dev/null; then
    echo "  (trivy not found locally — running via Docker image)"
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$HOME/.config/gcloud:/root/.config/gcloud:ro" \
      aquasec/trivy:latest image \
        --exit-code 1 \
        --severity "$TRIVY_SEVERITY" \
        --no-progress \
        --ignore-unfixed \
        "$FULL_IMAGE"
  else
    echo "ERROR: neither 'trivy' nor 'docker' found. Install trivy or set SKIP_SCAN=1 to bypass." >&2
    exit 1
  fi
  echo "✓ Trivy scan passed — no unfixed $TRIVY_SEVERITY vulnerabilities found."
fi

# ── 3. Verify GCP Secret Manager secrets ──────────────────────────────────────
echo ""
echo "▶ Checking GCP Secret Manager secrets..."
MISSING_SECRETS=()

for secret in GEMINI_API_KEY GITHUB_TOKEN; do
  if ! gcloud secrets describe "$secret" --project="$PROJECT" >/dev/null 2>&1; then
    MISSING_SECRETS+=("$secret")
  fi
done

if [[ ${#MISSING_SECRETS[@]} -gt 0 ]]; then
  echo "ERROR: The following required secrets are missing from GCP Secret Manager:" >&2
  for secret in "${MISSING_SECRETS[@]}"; do
    echo "  - $secret" >&2
  done
  echo "" >&2
  echo "Create them with:" >&2
  echo "  echo 'your-value' | gcloud secrets create <SECRET_NAME> --project=$PROJECT --replication-policy='automatic' --data-file=-" >&2
  echo "" >&2
  exit 1
fi
echo "✓ All required secrets are configured."

REQUIRED_SECRETS="GEMINI_API_KEY=GEMINI_API_KEY:latest,GITHUB_TOKEN=GITHUB_TOKEN:latest"

OPTIONAL_SECRETS=""
for secret in SECURITY_MONITORED_PACKAGES LLM_GLOBAL_CONTEXT; do
  if gcloud secrets describe "$secret" --project="$PROJECT" >/dev/null 2>&1; then
    OPTIONAL_SECRETS="${OPTIONAL_SECRETS},${secret}=${secret}:latest"
  fi
done

ALL_SECRETS="${REQUIRED_SECRETS}${OPTIONAL_SECRETS}"

# ── 4. Deploy Cloud Run Job ───────────────────────────────────────────────────
echo ""
echo "▶ Deploying Cloud Run Job '$TARGET_JOB_NAME'..."

SA_FLAG=()
if [[ -n "${SERVICE_ACCOUNT:-}" ]]; then
  SA_FLAG=("--service-account=$SERVICE_ACCOUNT")
fi

if gcloud run jobs describe "$TARGET_JOB_NAME" \
  --project="$PROJECT" \
  --region="$REGION" >/dev/null 2>&1; then
  gcloud run jobs update "$TARGET_JOB_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --image="$FULL_IMAGE" \
    --command="" \
    --args="" \
    "${SA_FLAG[@]+"${SA_FLAG[@]}"}" \
    --update-env-vars="$ENV_VARS_CSV" \
    --update-secrets="$ALL_SECRETS" \
    --max-retries=1
else
  if [[ "$ENVIRONMENT" != "dev" ]]; then
    echo "ERROR: Cloud Run job '$TARGET_JOB_NAME' does not exist. Refusing to auto-create in prod mode." >&2
    echo "       Re-run with --dev to create a dev job, or set JOB_NAME to an existing prod job." >&2
    exit 1
  fi

  echo "▶ Dev job '$TARGET_JOB_NAME' not found. Creating it..."
  gcloud run jobs create "$TARGET_JOB_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --image="$FULL_IMAGE" \
    --command="" \
    --args="" \
    "${SA_FLAG[@]+"${SA_FLAG[@]}"}" \
    --set-env-vars="$ENV_VARS_CSV" \
    --set-secrets="$ALL_SECRETS" \
    --max-retries=1
fi

echo ""
echo "✓ Deploy complete."
echo "  Deployed image : $FULL_IMAGE"
echo "  Run a job now  : ./wakellm.sh --run --$ENVIRONMENT"
