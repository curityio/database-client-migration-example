#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Get variables
#
. ../.env

#
# Get an access token
#
HTTP_STATUS=$(curl -s -k -X POST $TOKEN_ENDPOINT \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$MIGRATION_CLIENT_ID" \
    -d "client_secret=$MIGRATION_CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    -d "scope=$MIGRATION_CLIENT_SCOPE" \
    -o data.txt -w '%{http_code}')
if [ "$HTTP_STATUS" != '200'  ]; then
  exit 1
fi
ACCESS_TOKEN=$(cat data.txt | jq -r .access_token)
echo $ACCESS_TOKEN

#
# Get the schema
#
rm ./schema.graphql 2>/dev/null
./node_modules/.bin/get-graphql-schema "$GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT" -h "authorization=bearer $ACCESS_TOKEN" > ./schema.graphql
if [ "$HTTP_STATUS" != '200'  ]; then
  exit 1
fi

#
# Run the code generator to create TypeScript types
#
./node_modules/.bin/graphql-codegen --config codegen.ts
if [ $? -ne 0 ]; then
  exit 1
fi
