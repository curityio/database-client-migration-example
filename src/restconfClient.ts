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

import {ConfigurationClient} from './data/configurationClient.js';
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
    
    public async getClientsForProfile(profileId: string): Promise<ConfigurationClient[]> {
    
        const clientResponse = await this.getData(`base:profiles/profile=${profileId},oauth-service/settings/profile-oauth:authorization-server/client-store/config-backed`);
        const clients = clientResponse['profile-oauth:config-backed']['client'] as ConfigurationClient[];
        return clients.filter((c: any) => c.id !== this.environment.migrationClientId);
    }

    public async deleteClient(profileId: string, clientId: string): Promise<void> {

        const path = `base:profiles/profile=${profileId},oauth-service/settings/profile-oauth:authorization-server/client-store/config-backed/client=${clientId}`;
        await this.deleteData(path);
    }

    private async getData(path: string): Promise<any> {

        const response = await fetch(`${this.restConfApiBaseUrl}/${path}`, {
            method: 'GET',
            headers: this.getRequestHeaders(),
        });

        if (response.status !== 200) {
            throw new Error(`RESTCONF GET request to ${path} failed: ${response.statusText}`);
        }

        return await response.json();
    }

    private async deleteData(path: string): Promise<any> {

        const response = await fetch(`${this.restConfApiBaseUrl}/${path}`, {
            method: 'DELETE',
            headers: this.getRequestHeaders(),
        });

        if (response.status !== 204 && response.status !== 404) {
            console.log(`RESTCONF DELETE request to ${path} failed: ${response.statusText}`);
        }
    }

    private getRequestHeaders(): any {

        const credential = `${this.environment.restconfUsername}:${this.environment.restconfPassword}`;
        return {
            'accept': 'application/yang-data+json',
            'authorization': `Basic ${Buffer.from(credential).toString('base64')}`,
        };
    }
}
