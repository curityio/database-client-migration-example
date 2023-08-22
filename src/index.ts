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

import {ClientMapper} from './data/clientMapper.js'
import {getEnvironment} from './environment.js'
import {RestconfClient} from './restconfClient.js'
import {GraphqlClient} from './graphqlClient.js'

try {

    console.log('Preparing environment ...');
    const environment = getEnvironment();
    const mapper = new ClientMapper();

    console.log('Reading all profiles from configuration ...');
    const restconfClient = new RestconfClient(environment);
    const oauthProfileIds = await restconfClient.getProfileIds();

    console.log('Connecting to graphql ...');
    const graphqlClient = new GraphqlClient(environment);
    await graphqlClient.authenticate();

    for (const profileId of oauthProfileIds) {
        
        console.log(`Reading OAuth clients for profile '${profileId}' ...`);
        const clients = await restconfClient.getClientsForProfile(profileId);
        for (const client of clients) {
        
            console.log(`Migrating OAuth client '${client.id}' ...`);
            const databaseClient = mapper.convertToDatabaseClient(client);
            await graphqlClient.saveClient(databaseClient);
            console.log(`OAuth client '${client.id}' was migrated to the database successfully`);
        }
    }

} catch (e: any) {

    console.log(`Problem encountered: ${e.message}`);
}
