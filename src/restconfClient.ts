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

import {Client} from './data/clients.js';
import {Environment} from './environment.js';

/*
 * A class to download OAuth client information from the RESTCONF API
 */
export class RestconfClient {

    private readonly environment: Environment;
    private readonly restConfApiBaseUrl: string;

    constructor(environment: Environment) {

        this.environment = environment;
        this.restConfApiBaseUrl = `${this.environment.adminBaseUrl}/admin/api/restconf/data`;
    }

    public async getProfileIds(): Promise<string[]> {
        
        const profiles = await this.getData('base:profiles/profile/?fields=id;type');
        return profiles['base:profile']
            .filter((profile: any) => profile.type === 'profile-oauth:oauth-service')
            .map((profile: any) => profile.id);
    }
    
    public async getClientsForProfile(profileId: string): Promise<Client[]> {
    
        const clientResponse = await this.getData(`base:profiles/profile=${profileId},oauth-service/settings/profile-oauth:authorization-server/client-store/config-backed`);
        const clients = clientResponse['profile-oauth:config-backed']['client'] as Client[];
        return clients.filter((c: any) => c.id !== this.environment.migrationClientId);
    }

    private async getData(path: string): Promise<any> {

        const response = await fetch(`${this.restConfApiBaseUrl}/${path}`, {
            headers: this.getRequestHeaders(),
        });

        if (response.status !== 200) {
            throw new Error(`RESTCONF request to ${path} failed: ${response.statusText}`);
        }

        return await response.json();
    }

    private getRequestHeaders(): any {

        const credential = `${this.environment.restconfUsername}:${this.environment.restconfPassword}`;
        return {
            'accept': 'application/yang-data+json',
            'authorization': `Basic ${Buffer.from(credential).toString('base64')}`,
        };
    }
}
