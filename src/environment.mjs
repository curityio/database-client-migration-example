/*
 * Copyright (C) 2023 Curity AB. All rights reserved.
 *
 * The contents of this file are the property of Curity AB.
 * You may not copy or use this file, in either source code
 * or executable form, except in compliance with terms
 * set by Curity AB.
 *
 * For further information, please contact Curity AB.
 */

export function getEnvironment() {

    return {
        adminBaseUrl: getEnvironmentVariable("ADMIN_BASE_URL"),
        restconfUsername: getEnvironmentVariable("RESTCONF_USER"),
        restconfPassword: getEnvironmentVariable("RESTCONF_PASSWORD"),
        tokenEndpoint: getEnvironmentVariable("TOKEN_ENDPOINT"),
        graphqlClientManagementEndpoint: getEnvironmentVariable("GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT"),
        migrationClientId: getEnvironmentVariable("MIGRATION_CLIENT_ID"),
        migrationClientSecret: getEnvironmentVariable("MIGRATION_CLIENT_SECRET"),
    };
}

function getEnvironmentVariable(name) {

    const value = process.env[name];
    if (!value) {
        throw new Error(`Please set an environment variable of ${name} before running the migration program`);
    }

    return value;
}
