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

export class RestconfClient {

    constructor(environment) {

        this.environment = environment;

        this.restConfApiBaseUrl = `${this.environment.adminBaseUrl}/admin/api/restconf/data`;

        const credential = `${this.environment.restconfUsername}:${this.environment.restconfPassword}`;
        this.basicHeaders = {
            'accept': 'application/yang-data+json',
            'authorization': `Basic ${new Buffer.from(credential).toString('base64')}`,
        };
    }

    async getProfileIds() {
        
        const profiles = await this.getData('base:profiles/profile/?fields=id;type');
        return profiles['base:profile']
            .filter((profile) => profile.type === 'profile-oauth:oauth-service')
            .map((profile) => profile.id);
    }
    
    async getClientsForProfile(profileId) {
    
        const clientResponse = await this.getData(`base:profiles/profile=${profileId},oauth-service/settings/profile-oauth:authorization-server/client-store/config-backed`)
        const clients = clientResponse['profile-oauth:config-backed']['client']
        return clients.filter(c => c.id !== this.environment.migrationClientId)
    }

    async getData(path) {

        const response = await fetch(`${this.restConfApiBaseUrl}/${path}`, {
            headers: this.basicHeaders,
        });

        if (response.status !== 200) {
            throw new Error(`RESTCONF request to ${path} failed: ${response.statusText}`);
        }

        return await response.json();
    }
}
