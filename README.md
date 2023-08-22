# Database Clients Migration Example

[![Quality](https://img.shields.io/badge/quality-demo-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

A Node.js console app to demonstrate migrating clients from configuration to database storage.

## Prerequisites

First ensure that you have a working deployment of the Curity Identity Server, with GraphQL endpoints exposed.\
See the [Database Client Management with GraphQL](https://curity.io/resources/learn/graphql-client-management/) tutorial for details on the technical setup.\
Also ensure that an up to date version of Node.js is installed.

## Migration Behavior

The migration shows how to perform the following steps in a simple Node.js GraphQL client:

- Read existing clients from all token service profiles using the RESTCONF API
- Translate them to the GraphQL client format
- Save them to a JDBC data source by calling the GraphQL API

## Migration Configuration

The Node.js app needs to be authorized to call GraphQL authorization requirements.\
It must therefore get an access token with the right permissions.\
The `migration-configuration.xml` file shows the approach for doing this:

- A `migration-client` is created, which uses the client credentials flow to get an access token
- The access tokens uses a custom `database-clients` scope
- A GraphQL authorization manager enables access tokens with this scope to manage database clients
- This in an attribute authorization manager, and is configured against the token service profile

## Running the Migration Process

First, edit the `src/emvorpmigrate.sh` script to point to your own environment.\
The default settings point to a local development system:

```text
export RESTCONF_USER='admin'
export RESTCONF_PASSWORD='Password1'
export ADMIN_BASE_URL='http://localhost:6749'
export TOKEN_ENDPOINT='http://localhost:8443/oauth/v2/oauth-token'
export GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT='http://localhost:8443/client-management'
export MIGRATION_CLIENT_ID='migration-client'
export MIGRATION_CLIENT_SECRET='Password1'
export MIGRATION_CLIENT_SCOPE='database-clients'
```

Then run the script



, or `npm start` to perform the migration, and view results.\
Once the migration has completed, be sure to remove any migrated clients from configuration based storage.\
This will avoid the potential for unexpected behavior.

## More information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.