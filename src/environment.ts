/*
 *  Copyright 2023 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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
