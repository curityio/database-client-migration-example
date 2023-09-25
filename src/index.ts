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

import {ClientMapper} from './data/clientMapper.js'
import {getEnvironment, isClientToMigrate} from './environment.js'
import {RestconfClient} from './restconfClient.js'
import {GraphqlClient} from './graphqlClient.js'

console.log('Preparing environment ...');
const environment = getEnvironment();
const restconfClient = new RestconfClient(environment);
const mapper = new ClientMapper(environment.migrationTag);
const graphqlClient = new GraphqlClient(environment);

console.log('Reading all profiles from configuration ...');
const oauthProfileIds = await restconfClient.getProfileIds();

console.log('Initializing GraphQL client ...');
await graphqlClient.authenticate();

for (const profileId of oauthProfileIds) {
    
    console.log(`Reading OAuth clients for profile '${profileId}' ...`);
    const configClients = await restconfClient.getClientsForProfile(profileId);
    for (const configClient of configClients) {

        if (isClientToMigrate(configClient.id)) {

            console.log(`Migrating OAuth client '${configClient.id}' ...`);
            const databaseClient = mapper.convertToDatabaseClient(configClient);
            if (databaseClient) {

                await graphqlClient.saveClient(databaseClient);
                console.log(`OAuth client '${configClient.id}' was succesfully migrated to database storage`);

            } else {

                console.log(`OAuth client '${configClient.id}' does not yet support database storage`);
            }
        }
    }
}
