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
import {getEnvironment, isClientToIgnore} from './environment.js'
import {RestconfClient} from './restconfClient.js'
import {GraphqlClient} from './graphqlClient.js'

try {

    console.log('Preparing environment ...');
    const environment = getEnvironment();
    const restconfClient = new RestconfClient(environment);
    const mapper = new ClientMapper();
    const graphqlClient = new GraphqlClient(environment);

    console.log('Reading all profiles from configuration ...');
    const oauthProfileIds = await restconfClient.getProfileIds();

    console.log('Initializing GraphQL client ...');
    await graphqlClient.authenticate();

    for (const profileId of oauthProfileIds) {
        
        console.log(`Reading OAuth clients for profile '${profileId}' ...`);
        const configClients = await restconfClient.getClientsForProfile(profileId);
        for (const configClient of configClients) {

            if (!isClientToIgnore(configClient.id)) {

                console.log(`Migrating OAuth client '${configClient.id}' ...`);
                const databaseClient = mapper.convertToDatabaseClient(configClient);
                await graphqlClient.saveClient(databaseClient);
                console.log(`OAuth client '${configClient.id}' was succesfully migrated to database storage`);
            }
        }
    }

} catch (e: any) {

    console.log(`Problem encountered: ${e.message}`);
}
