#!/bin/bash
ZIP_PATH="$1"
BHCE_PASS="$2"
BHCE_URL="${3:-http://localhost:8080}"
[ -z "$ZIP_PATH" ] || [ -z "$BHCE_PASS" ] && { echo "[-] Missing args"; exit 1; }
[ -f "$ZIP_PATH" ] || { echo "[-] ZIP not found: $ZIP_PATH"; exit 1; }
TOKEN=$(curl -s -X POST "$BHCE_URL/api/v2/login" \
    -H "Content-Type: application/json" \
    -d "{\"login_method\":\"secret\",\"username\":\"admin\",\"secret\":\"$BHCE_PASS\"}" \
    | jq -r '.data.session_token')
[ -z "$TOKEN" ] || [ "$TOKEN" = "null" ] && { echo "[-] Auth failed"; exit 1; }
UPLOAD_ID=$(curl -s -X POST "$BHCE_URL/api/v2/file-upload/start" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" | jq -r '.data.id')
curl -s -X POST "$BHCE_URL/api/v2/file-upload/$UPLOAD_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/zip" \
    --data-binary @"$ZIP_PATH" > /dev/null
curl -s -X POST "$BHCE_URL/api/v2/file-upload/$UPLOAD_ID/end" \
    -H "Authorization: Bearer $TOKEN" > /dev/null
echo "[+] Uploaded: $(basename $ZIP_PATH)"
