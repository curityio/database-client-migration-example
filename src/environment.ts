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

import dotenv from 'dotenv';
dotenv.config();

export interface Environment {
    adminBaseUrl: string;
    restconfUsername: string;
    restconfPassword: string;
    tokenEndpoint: string;
    graphqlClientManagementEndpoint: string;
    migrationClientId: string;
    migrationClientSecret: string;
    migrationClientScope: string;
}

export function getEnvironment(): Environment {

    return {
        adminBaseUrl: getEnvironmentVariable("ADMIN_BASE_URL"),
        restconfUsername: getEnvironmentVariable("RESTCONF_USER"),
        restconfPassword: getEnvironmentVariable("RESTCONF_PASSWORD"),
        tokenEndpoint: getEnvironmentVariable("TOKEN_ENDPOINT"),
        graphqlClientManagementEndpoint: getEnvironmentVariable("GRAPHQL_CLIENT_MANAGEMENT_ENDPOINT"),
        migrationClientId: getEnvironmentVariable("MIGRATION_CLIENT_ID"),
        migrationClientSecret: getEnvironmentVariable("MIGRATION_CLIENT_SECRET"),
        migrationClientScope: getEnvironmentVariable("MIGRATION_CLIENT_SCOPE"),
    };
}

export function isClientToIgnore(id: string): boolean {
    
    return id === getEnvironmentVariable("MIGRATION_CLIENT_ID") ||
           id == 'devops_dashboard_restconf_client';
}

function getEnvironmentVariable(name: string) {

    const value = process.env[name];
    if (!value) {
        throw new Error(`Please set an environment variable of ${name} before running the migration program`);
    }

    return value;
}
