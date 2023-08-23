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

import {jsonToGraphQLQuery} from 'json-to-graphql-query';
import {DatabaseClient} from './data/databaseClient.js';
import {Environment} from './environment.js';
import {getHttpErrorAsText, getGraphqlErrorAsText} from './utils.js'

/*
 * A class to send database client information to GraphQL APIs
 */
export class GraphqlClient {

    private readonly environment: Environment;
    private accessToken: string;

    constructor(environment: Environment) {
        this.environment = environment;
        this.accessToken = '';
    }

    public async authenticate(): Promise<void> {

        const credential = `${this.environment.migrationClientId}:${this.environment.migrationClientSecret}`;
        const response = await fetch(this.environment.tokenEndpoint, {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'authorization': `Basic ${Buffer.from(credential).toString('base64')}`,
            },
            body: `grant_type=client_credentials&scope=${this.environment.migrationClientScope}`,
        });

        if (response.status !== 200) {
            const message = await getHttpErrorAsText(response);
            throw new Error(`Token endpoint request failed: ${message}`);
        }

        const tokens = await response.json();
        this.accessToken = tokens.access_token;
    }

    public async saveClient(databaseClient: DatabaseClient): Promise<void> {

        const command = {
            mutation: {
                createDatabaseClient: {
                    __args: {
                        input: {
                            fields: databaseClient,
                        },
                    },
                    client: {
                        client_id: true,
                    },
                },
            }
        };

        try {
            
            await this.runGraphqlCommand('saveClient', command);

        } catch(e: any) {

            if (!e.message?.indexOf('already registered')) {
                throw e;
            }
        }
    }

    private async runGraphqlCommand(name: string, command: any): Promise<any> {
        
        const commandText = jsonToGraphQLQuery(command, { pretty: true });

        const response = await fetch(this.environment.graphqlClientManagementEndpoint, {
            method: 'POST',
            headers: {
              'authorization': `bearer ${this.accessToken}`,
              'content-type': 'application/graphql',
            },
            body: commandText,
        });

        if (response.status !== 200) {
            const message = await getHttpErrorAsText(response);
            throw new Error(`GRAPHQL ${name} request failed: ${response.status}: ${message}`);
        }

        const responseData = await response.json();
        if (responseData.errors) {
            const message = getGraphqlErrorAsText(responseData);
            throw new Error(`GRAPHQL ${name} request failed: ${message}`);
        }

        return responseData;
    }
}
