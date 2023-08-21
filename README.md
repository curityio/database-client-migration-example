# Database Clients Migration Example

[![Quality](https://img.shields.io/badge/quality-demo-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

A Node.js example to demonstrate the approach for migrating clients from configuration to database storage.

## Prerequisites

First ensure that you have a deployment of the Curity Identity Server, with working GraphQL endpoints.\
See the [Database Client Management with GraphQL](https://curity.io/resources/learn/graphql-client-management/) tutorial for details on the technical setup.

## Migration Behavior

The migration shows how to perform the following steps in a simple Node.js GraphQL client:

- Read existing clients from all token service profiles using the RESTCONF API
- Translate them to the GraphQL client format
- Save them to a JDBC data source by calling the GraphQL API

## Migration Configuration

The Node.js app needs to be authorized to call GraphQL authorization requirements.\
It must therefore get an access token with the right permissions.\
The `migration-configuration.xml` file shows the approach for doing this:

- A `migration-client` is created that uses a custom `database-clients` scope
- This scope is granted GraphQL database client access
- A rule list is added to the attribute authorization manager configured against the token profile

## Running the Migration Process

First, update the `migrate.sh` script to point to your own environment.\
The default settings point to a local development system:

```text
export RESTCONF_USER='admin'
export RESTCONF_PASSWORD='Password1'
export ADMIN_BASE_URL='http://localhost:6749'
export TOKEN_ENDPOINT='http://localhost:8443/oauth/v2/oauth-token'
export GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT='http://localhost:8443/client-management'
export MIGRATION_CLIENT_ID='migration-client'
export MIGRATION_CLIENT_SECRET='Password1'
```

Then run the migration and view output to see results:

```bash
npm start
```

Once the migration has completed, be sure to remove any migrated clients from configuration based storage.\
This will remove the potential for unexpected behavior.

## More information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.