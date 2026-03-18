#!/usr/bin/env bash

set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
WORKSPACE="${1:-dev}"

BUCKET_NAME="fintech-payment-events-${WORKSPACE}"
TABLE_NAME="transactions-${WORKSPACE}"
FUNCTION_NAME="process-payment-${WORKSPACE}"
POLICY_NAME="lambda-payment-processor-policy-${WORKSPACE}"

AWS_CMD=(aws --endpoint-url "${AWS_ENDPOINT_URL}" --region "${AWS_DEFAULT_REGION}")

normalize_text() {
  echo "$1" | tr -d '\r' | xargs
}

fail() {
  echo "[FAIL] $1"
  exit 1
}

echo "--- Running compliance checks for workspace: ${WORKSPACE} ---"

for required_cmd in aws terraform; do
  if ! command -v "${required_cmd}" >/dev/null 2>&1; then
    fail "Required command not found: ${required_cmd}"
  fi
done

# Check 1: S3 Public Access Block
block_public_acls=$("${AWS_CMD[@]}" s3api get-public-access-block --bucket "${BUCKET_NAME}" --query 'PublicAccessBlockConfiguration.BlockPublicAcls' --output text)
block_public_policy=$("${AWS_CMD[@]}" s3api get-public-access-block --bucket "${BUCKET_NAME}" --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text)
ignore_public_acls=$("${AWS_CMD[@]}" s3api get-public-access-block --bucket "${BUCKET_NAME}" --query 'PublicAccessBlockConfiguration.IgnorePublicAcls' --output text)
restrict_public_buckets=$("${AWS_CMD[@]}" s3api get-public-access-block --bucket "${BUCKET_NAME}" --query 'PublicAccessBlockConfiguration.RestrictPublicBuckets' --output text)

block_public_acls="$(normalize_text "${block_public_acls}")"
block_public_policy="$(normalize_text "${block_public_policy}")"
ignore_public_acls="$(normalize_text "${ignore_public_acls}")"
restrict_public_buckets="$(normalize_text "${restrict_public_buckets}")"

block_public_acls="${block_public_acls,,}"
block_public_policy="${block_public_policy,,}"
ignore_public_acls="${ignore_public_acls,,}"
restrict_public_buckets="${restrict_public_buckets,,}"

if [[ "${block_public_acls}" == "true" && "${block_public_policy}" == "true" && "${ignore_public_acls}" == "true" && "${restrict_public_buckets}" == "true" ]]; then
  echo "[OK] S3 public access block is fully enabled."
else
  fail "S3 public access block is not fully enabled."
fi

# Check 2: S3 Versioning
bucket_versioning=$("${AWS_CMD[@]}" s3api get-bucket-versioning --bucket "${BUCKET_NAME}" --query 'Status' --output text)
bucket_versioning="$(normalize_text "${bucket_versioning}")"
if [[ "${bucket_versioning}" == "Enabled" ]]; then
  echo "[OK] S3 bucket versioning is enabled."
else
  fail "S3 bucket versioning is not enabled."
fi

# Check 3: S3 Encryption
bucket_sse_algo=$("${AWS_CMD[@]}" s3api get-bucket-encryption --bucket "${BUCKET_NAME}" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)
bucket_kms_key=$("${AWS_CMD[@]}" s3api get-bucket-encryption --bucket "${BUCKET_NAME}" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' --output text)
bucket_sse_algo="$(normalize_text "${bucket_sse_algo}")"
bucket_kms_key="$(normalize_text "${bucket_kms_key}")"

if [[ "${bucket_sse_algo}" == "aws:kms" && "${bucket_kms_key}" == arn:aws:kms:* ]]; then
  echo "[OK] S3 bucket encryption is aws:kms and uses a CMK."
else
  fail "S3 bucket encryption is not configured with aws:kms and CMK."
fi

# Check 4: DynamoDB Encryption
ddb_sse_status=$("${AWS_CMD[@]}" dynamodb describe-table --table-name "${TABLE_NAME}" --query 'Table.SSEDescription.Status' --output text)
ddb_kms_arn=$("${AWS_CMD[@]}" dynamodb describe-table --table-name "${TABLE_NAME}" --query 'Table.SSEDescription.KMSMasterKeyArn' --output text)
ddb_sse_status="$(normalize_text "${ddb_sse_status}")"
ddb_kms_arn="$(normalize_text "${ddb_kms_arn}")"

if [[ "${ddb_sse_status}" == "ENABLED" && "${ddb_kms_arn}" == arn:aws:kms:* ]]; then
  echo "[OK] DynamoDB SSE is enabled and uses a CMK."
else
  fail "DynamoDB SSE is not enabled with a CMK."
fi

# Check 5: IAM wildcard action check
policy_arn=$("${AWS_CMD[@]}" iam list-policies --scope Local --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn | [0]" --output text)
policy_arn="$(normalize_text "${policy_arn}")"
if [[ -z "${policy_arn}" || "${policy_arn}" == "None" ]]; then
  fail "Could not find IAM policy: ${POLICY_NAME}"
fi

policy_version=$("${AWS_CMD[@]}" iam get-policy --policy-arn "${policy_arn}" --query 'Policy.DefaultVersionId' --output text)
policy_version="$(normalize_text "${policy_version}")"
actions=$("${AWS_CMD[@]}" iam get-policy-version --policy-arn "${policy_arn}" --version-id "${policy_version}" --query 'PolicyVersion.Document.Statement[].Action' --output text)

for action in ${actions}; do
  case "${action}" in
    logs:CreateLogGroup|logs:CreateLogStream|logs:PutLogEvents)
      ;;
    *"*")
      fail "Forbidden wildcard action found in IAM policy: ${action}"
      ;;
    *)
      ;;
  esac
done

echo "[OK] IAM policy has no forbidden wildcard actions."

# Check 6: Lambda function exists
function_arn=$("${AWS_CMD[@]}" lambda get-function --function-name "${FUNCTION_NAME}" --query 'Configuration.FunctionArn' --output text)
function_arn="$(normalize_text "${function_arn}")"
if [[ -z "${function_arn}" || "${function_arn}" == "None" ]]; then
  fail "Lambda function not found: ${FUNCTION_NAME}"
fi

echo "[OK] Lambda function exists."

# Check 7: S3 bucket notification trigger to Lambda
action_count=$("${AWS_CMD[@]}" s3api get-bucket-notification-configuration --bucket "${BUCKET_NAME}" --query "length(LambdaFunctionConfigurations[?LambdaFunctionArn=='${function_arn}' && contains(Events, 's3:ObjectCreated:*')])" --output text)
action_count="$(normalize_text "${action_count}")"
if [[ "${action_count}" -ge 1 ]]; then
  echo "[OK] S3 bucket notification triggers Lambda on s3:ObjectCreated:*."
else
  fail "S3 bucket notification is missing required Lambda trigger for object creation."
fi

echo "--- All compliance checks passed. ---"
