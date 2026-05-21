# Deployment

## Prerequisites

- `gcloud` CLI authenticated (`gcloud auth login`, `gcloud auth application-default login`)
- `.env` file populated from `.env.example`
- GCP APIs enabled (one-time, see below)
- `trivy` installed — https://aquasecurity.github.io/trivy/latest/getting-started/installation/ (or Docker as fallback)

## One-time GCP setup

### Enable APIs

```bash
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  --project=YOUR_PROJECT
```

### Create Artifact Registry repository

```bash
gcloud artifacts repositories create wakellm-security \
  --repository-format=docker \
  --location=europe-west1 \
  --project=YOUR_PROJECT
```

### Create service account

```bash
gcloud iam service-accounts create wakellm-security-runner \
  --display-name="wakellm-security Cloud Run runner" \
  --project=YOUR_PROJECT

# Allow it to read secrets
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member="serviceAccount:wakellm-security-runner@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Create required secrets

```bash
echo -n "your-gemini-api-key" | gcloud secrets create gemini-api-key \
  --project=YOUR_PROJECT --replication-policy=automatic --data-file=-

echo -n "ghp_your_token" | gcloud secrets create github-token \
  --project=YOUR_PROJECT --replication-policy=automatic --data-file=-
```

See [Configuration](configuration.md) for optional secrets.

---

## .env setup

Copy `.env.example` to `.env` and fill in at minimum:

```bash
PROJECT=your-gcp-project-id
REGION=europe-west1
SERVICE_ACCOUNT=wakellm-security-runner@your-gcp-project-id.iam.gserviceaccount.com
PROD_JOB_NAME=wakellm-security
DEV_JOB_NAME=wakellm-security-dev
REPO=wakellm-security
IMAGE_NAME=wakellm-security
```

---

## Deploying

### Dev deploy (creates job if missing)

```bash
./wakellm.sh --deploy --dev
```

This:
1. Submits the image to **Cloud Build** (builds from the root `Dockerfile`)
2. Tags the image `:latest` in Artifact Registry
3. Runs a **Trivy** vulnerability scan — fails if unfixed HIGH/CRITICAL CVEs are found
4. Checks that `gemini-api-key` and `github-token` secrets exist in Secret Manager
5. **Creates** the dev Cloud Run Job if it doesn't exist; **updates** it if it does

### Prod deploy (update-only)

```bash
./wakellm.sh --deploy --prod
```

Identical to dev deploy, but:
- Targets `PROD_JOB_NAME` instead of `DEV_JOB_NAME`
- **Refuses to auto-create** the job — the prod job must already exist (safety guard)

### Skip Trivy scan

```bash
SKIP_SCAN=1 ./wakellm.sh --deploy --dev
```

### Override image tag

By default the tag is the short git SHA. Override with:

```bash
TAG=v1.2.3 ./wakellm.sh --deploy --prod
```

---

## Running a job

```bash
# Run prod job (default)
./wakellm.sh --run

# Run dev job
./wakellm.sh --run --dev
```

This executes `gcloud run jobs execute <JOB_NAME> --args='securityDigest' --wait`. The `--wait` flag blocks until the execution completes.

### With social media drafts

```bash
./wakellm.sh --run --dev --social
```

This passes `securityDigest --social` as args to the Cloud Run job. After the execution completes, `wakellm.sh` automatically:

1. Retrieves the stdout log for the execution via `gcloud logging read`
2. Reconstructs the JSON output (Cloud Run logs each printed line separately)
3. Extracts the `drafts` block and writes `./drafts/YYYY-MM-DD-HHmm.md`

The markdown file has three ready-to-paste sections:

```
# Security Digest — 2026-05-22

---
## Reddit
**Title:** 3 npm/supply-chain threats this week: CVE-2025-30066, ...
[full markdown post]

---
## Twitter/X Thread
**Tweet 1** (87 chars):
> 3 npm/supply-chain threats this week ...
...

---
## LinkedIn
[professional narrative with hashtags]
```

Tweets that exceed 280 characters are flagged with `*** OVER 280 ***` so you can trim before posting.

After posting to Reddit, replace `[REDDIT_LINK]` in the Twitter/X closing tweet and LinkedIn post with the actual URL.

### Viewing output

Cloud Run captures stdout as a single log entry. View it in the GCP Console → Cloud Run → Jobs → Executions, or via:

```bash
gcloud logging read \
  'resource.type="cloud_run_job" AND textPayload!=""' \
  --project=YOUR_PROJECT \
  --limit=50 \
  --format='value(textPayload)'
```

Diagnostics (severity, fetch counts, triage events) go to **stderr** in structured JSON format and appear in Cloud Logging with proper severity labels.

---

## Cloud Scheduler (optional)

To run the job on a schedule:

```bash
gcloud scheduler jobs create http wakellm-security-daily \
  --schedule="0 8 * * *" \
  --time-zone="Europe/London" \
  --uri="https://run.googleapis.com/v1/namespaces/YOUR_PROJECT/jobs/wakellm-security:run" \
  --message-body='{}' \
  --oauth-service-account-email="wakellm-security-runner@YOUR_PROJECT.iam.gserviceaccount.com" \
  --location=europe-west1 \
  --project=YOUR_PROJECT
```

Grant the scheduler service account permission to invoke the job:

```bash
gcloud run jobs add-iam-policy-binding wakellm-security \
  --region=europe-west1 \
  --member="serviceAccount:wakellm-security-runner@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --project=YOUR_PROJECT
```

---

## Dockerfile

The image is built in two stages:

| Stage | Base | Content |
|---|---|---|
| `runtime` | `python:3.12-alpine` | `src/`, `config/`, `requirements.txt`. Non-root user `appuser`. |
| `dev` | `runtime` | Adds `requirements-dev.txt` and `tests/`. Used for running `pytest` inside the container. |

Cloud Run uses the `runtime` stage. The `dev` stage is used in CI or local container testing:

```bash
docker build --target dev -t wakellm-security:dev .
docker run --rm --env-file .env wakellm-security:dev pytest tests/python/ -v
```
