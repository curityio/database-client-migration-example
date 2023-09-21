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
                console.log(JSON.stringify(databaseClient, null, 2));
                throw new Error(errorText);
            }
        }

        if (!result.data) {
            throw new Error('GRAPHQL response contained no data');
        }

        return result.data;
    }
}
