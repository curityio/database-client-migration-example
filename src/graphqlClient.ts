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

    /*
     * Run a client credentials flow to get an access token with GraphQL permissions
     */
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
        console.log(this.accessToken);
    }

    /*
     * Send a mutation with the input object as a variable
     * This type of request sends a JSON request body with 'operationName', 'query' and 'variables' fields
     */
    public async saveClient(databaseClient: CreateDatabaseClientInput): Promise<CreateDatabaseClientPayload> {

        const options: ClientOptions = {
            url: this.environment.graphqlClientManagementEndpoint,
            fetchOptions: {
                headers: {
                    'authorization': `bearer ${this.accessToken}`,
                    'content-type': 'application/json',
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
        
        if (result.error?.response?.status) {
            if (result.error.response.status != 200) {
                throw new Error(`GRAPHQL request failed: status: ${result.error.response.status}`);
            }
        }

        if (result.error?.networkError) {
            throw new Error(`GRAPHQL request failed: ${result.error?.networkError}`);
        }

        if (result.error?.graphQLErrors) {
            const errorText = getGraphqlErrorAsText(result.error.graphQLErrors);
            if (errorText.indexOf('already registered') === -1) {
                throw new Error(errorText);
            }
        }

        if (!result.data) {
            throw new Error('GRAPHQL response contained no data');
        }

        return result.data;
    }
}
