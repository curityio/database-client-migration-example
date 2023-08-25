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

import {Client, ClientOptions, fetchExchange, gql} from '@urql/core';
import {CreateDatabaseClientInput, CreateDatabaseClientPayload} from './data/databaseClient.js';
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

    public async saveClient(databaseClient: CreateDatabaseClientInput): Promise<CreateDatabaseClientPayload | null> {

        const options: ClientOptions = {
            url: this.environment.graphqlClientManagementEndpoint,
            fetchOptions: {
                headers: {
                    'authorization': `bearer ${this.accessToken}`,
                    'content-type': 'application/graphql',
                },
            },
           exchanges: [fetchExchange],
        };
        const client = new Client(options);

        const mutation = gql`
            mutation createDatabaseClient($input: CreateDatabaseClientInput!) {
                createDatabaseClient(input: $input ) {
                    client {
                        client_id
                    }
                }
            }`;
        const variables = { input: databaseClient };
        
        const result = await client.mutation<CreateDatabaseClientPayload>(mutation, variables);
        if (result.error?.networkError || result.error?.response?.status != 200) {
            
            if (result.error?.response?.status) {
                throw new Error(`GRAPHQL request failed: status: ${result.error.response.status}`);
            } else {
                throw new Error(`GRAPHQL request failed: ${result.error?.networkError}`);
            }
        }

        if (result.error?.graphQLErrors) {
            throw new Error(getGraphqlErrorAsText(result.error.graphQLErrors));
        }

        return result.data || null;
    }
}
