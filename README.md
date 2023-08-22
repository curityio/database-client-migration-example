# Database Clients Migration Example

[![Quality](https://img.shields.io/badge/quality-demo-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

A Node.js console app to show how to migrate OAuth clients from configuration to database storage:

- Read existing clients from all token service profiles using the RESTCONF API
- Translate them to the GraphQL client format
- Save them to a JDBC data source by calling the GraphQL API

## Prerequisites

First ensure that you have a working deployment of the Curity Identity Server, with GraphQL endpoints exposed.\
See the [Database Client Management with GraphQL](https://curity.io/resources/learn/graphql-client-management/) tutorial for details on the technical setup.\
Also ensure that an up to date version of Node.js is installed.

## Configure Migration

First, edit the `.env` file to point to your own environment.\
The default settings point to the [DevOps dashboard example deployment](https://github.com/curityio/devops-dashboard-example).

```text
RESTCONF_USER='admin'
RESTCONF_PASSWORD='Password1'
ADMIN_BASE_URL='http://localhost:6749'
TOKEN_ENDPOINT='http://localhost:8443/oauth/v2/oauth-token'
GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT='http://localhost:8443/client-management'
MIGRATION_CLIENT_ID='migration-client'
MIGRATION_CLIENT_SECRET='Password1'
MIGRATION_CLIENT_SCOPE='database-clients'
```

This Node.js migration app needs to send access tokens that are authorized to call GraphQL authorization requirements.\
The `migration-configuration.xml` file contains settings that can be applied to the DevOps dashboard example deployment:

- A `migration-client` is created, which uses the client credentials flow to get an access token
- The access token uses a custom `database-clients` scope
- The GraphQL authorization manager enables access tokens with this scope to manage database clients
- This authorization manager is configured against the token service profile

The setup can be adapted to your own requirements.

## Run the Migration

The migration can be run using the following commands:

```bash
npm install
npm start
```

Once the migration has completed, be sure to remove any migrated clients from configuration based storage.\
Doing so will remove the potential for unexpected behavior.

## More information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.