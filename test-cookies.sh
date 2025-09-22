#!/bin/bash

validate_cookie() {
    local cookie_value="$1"
    local server_type="$2"

    if [ -n "$cookie_value" ]; then
        echo "  Cookie validation test:"
        # Test with valid cookie
        if [ "$server_type" = "local" ]; then
            result=$(curl -s "http://localhost:8080/healthz" -H "Cookie: ic_redirect=$cookie_value" 2>/dev/null)
        else
            result=$(curl -s "https://intercom-auth.lehotsky.net/healthz" -H "Cookie: ic_redirect=$cookie_value" 2>/dev/null)
        fi

        # Decode and check expiration manually
        payload=$(echo "$cookie_value" | cut -d. -f1 | base64 -d 2>/dev/null)
        if [ $? -eq 0 ]; then
            exp=$(echo "$payload" | jq -r '.exp' 2>/dev/null)
            current_time=$(date +%s)
            if [ "$exp" -gt "$current_time" ]; then
                echo "  ✅ Cookie is valid (expires: $(date -r $exp))"
            else
                echo "  ❌ Cookie is expired (expired: $(date -r $exp))"
            fi
        else
            echo "  ❌ Cookie format invalid"
        fi
    fi
}

echo "=== Testing Local Server ==="
COOKIE=$(curl -i "http://localhost:8080/login?return_to=https%3A%2F%2Friscv.org%2Ftest" -H "Referer: https://riscv.org/" 2>/dev/null | grep "Set-Cookie:" | grep -o 'ic_redirect=[^;]*' | cut -d= -f2)
if [ -n "$COOKIE" ]; then
    echo "Local cookie payload:"
    echo $COOKIE | cut -d. -f1 | base64 -d | jq
    validate_cookie "$COOKIE" "local"
else
    echo "No cookie received from local server"
fi

echo ""
echo "=== Testing lehotsky.net Server ==="
COOKIE=$(curl -i "https://intercom-auth.lehotsky.net/login?return_to=https%3A%2F%2Flehotsky.net%2Ftest" -H "Referer: https://lehotsky.net/" 2>/dev/null | grep -i "set-cookie:" | grep -o 'ic_redirect=[^;]*' | cut -d= -f2)
if [ -n "$COOKIE" ]; then
    echo "lehotsky.net cookie payload:"
    echo $COOKIE | cut -d. -f1 | base64 -d | jq
    validate_cookie "$COOKIE" "production"
else
    echo "No cookie received from lehotsky.net server"
fi