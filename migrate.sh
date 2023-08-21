#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

export RESTCONF_USER='admin'
export RESTCONF_PASSWORD='Password1'
export ADMIN_BASE_URL='http://localhost:6749'
export TOKEN_ENDPOINT='http://localhost:8443/oauth/v2/oauth-token'
export GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT='http://localhost:8443/client-management'
export MIGRATION_CLIENT_ID='migration-client'
export MIGRATION_CLIENT_SECRET='Password1'

node src/index.mjs
