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

import {getResponseErrorMessage, getGraphqlErrorMessage} from './utils.mjs'

export class GraphqlClient {

    constructor(environment) {
        this.environment = environment;
        this.accessToken = '';
    }

    async authenticate() {

        const credential = `${this.environment.migrationClientId}:${this.environment.migrationClientSecret}`;
        const response = await fetch(this.environment.tokenEndpoint, {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'authorization': `Basic ${new Buffer.from(credential).toString('base64')}`,
            },
            body: `grant_type=client_credentials&scope=${this.environment.migrationClientScope}`,
        });

        if (response.status !== 200) {
            const message = await getResponseErrorMessage(response);
            throw new Error(`Token endpoint request failed: ${message}`);
        }

        const tokens = await response.json();
        this.accessToken = tokens.access_token;
        console.log(this.accessToken);
    }

    async saveClient(clientData) {

        if (clientData.client_id !== 'introspect-client') {
            return;
        }

        const data = `
              mutation createDatabaseClient {
                createDatabaseClient(input: {
                fields: ${JSON.stringify(clientData)} {
                client {
                    client_id
                    capabilities {
                      code {
                        type
                      }
                    }
                    redirect_uris
                }
              }
            }
        `;
        
        const response = await fetch(this.environment.graphqlClientManagementEndpoint, {
            method: 'POST',
            headers: {
              'authorization': `bearer ${this.accessToken}`,
              'content-type': 'application/graphql',
            },
            body: data,
        });

        if (response.status !== 200) {
            const message = await getResponseErrorMessage(response);
            throw new Error(`GRAPHQL request to save client ${clientData.client_id} failed: ${response.status}: ${message}`);
        }

        const responseData = await response.json();
        if (responseData.errors) {
            const message = await getGraphqlErrorMessage(responseData);
            throw new Error(`GRAPHQL request to save client ${clientData.client_id} failed: ${message}`);
        }
    }
}
