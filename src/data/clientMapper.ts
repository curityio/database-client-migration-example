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

import {Client} from './clients.js';
import {ClientAuthentication, Code, DatabaseClient, Introspection} from './database-clients.js';

export class ClientMapper {

    public convertToDatabaseClient(client: Client): DatabaseClient {

        const databaseClient: DatabaseClient = {
            
            // Easy to translate values
            access_token_ttl: client['access-token-ttl'] || null,
            allowed_origins: client['allowed-origins'] || null,
            application_url: client['application-url'] || null,
            audiences: client['audience'] || [],
            claim_mapper_id: client['claims-mapper'] || null,
            client_id: client['id'],
            description: client['description'] || null,
            logo_uri: client['logo'] || null,
            name: client['client-name'] || null,
            policy_uri: client['privacy-policy-url'] || null,
            redirect_uri_validation_policy_id: client['redirect-uri-validation-policy'] || null,
            redirect_uris: client['redirect-uris'] || null,
            require_secured_authorization_response: Array.isArray(client['require-secured-authorization-response']) ? true : false,
            scopes: client['scope'] || [],
            status: client['enabled'] ? 'ACTIVE' : 'INACTIVE',
            userinfo_signed_issuer_id: client['signed-userinfo']?.['userinfo-token-issuer'] || null,
            tos_uri: client['terms-of-service-url'] || null,
            validate_port_on_loopback_interfaces: client['validate-port-on-loopback-interfaces'] || null,

            // Not done properly yet
            allow_per_request_redirect_uris: null,
            capabilities: {} as any,
            client_authentication: {} as any,
            id_token: null,
            properties: {},
            refresh_token: null,
            request_object: null,
            sector_identifier: null,
            subject_type: 'public',
            tags: null,
            user_authentication: null,
        };

        this.setCapabilities(databaseClient, client);
        this.setClientAuthentication(databaseClient, client);
        this.setIdToken(databaseClient, client);
        this.setRefreshToken(databaseClient, client);
        this.setUserAuthentication(databaseClient, client);

        return databaseClient;
    }

    private setCapabilities(databaseClient: DatabaseClient, client: Client): void {

        databaseClient.capabilities = {
            assertion: null,
            assisted_token: null,
            backchannel: null,
            client_credentials: null,
            code: null,
            haapi: null,
            implicit: null,
            introspection: null,
            resource_owner_password: null,
            token_exchange: null,
        };

        if (client.capabilities.code) {
            databaseClient.capabilities.code = {
                proof_key: null,
                require_pushed_authorization_request: null,
                type: Code.CODE,
            }
        }

        if (client.capabilities.introspection) {
            databaseClient.capabilities.introspection = {
                type: Introspection.INTROSPECTION,
            }
        }
    }

    private setClientAuthentication(databaseClient: DatabaseClient, client: Client): void {

        // JWKS URI is unsupported for database clients, and is migrated with a type of no-authentication
        const clientAuthentication: ClientAuthentication = {
            primary: {
            },
            secondary: null,
            secondary_verifier_expiration: null,
        };

        if (client['asymmetric-key']) {

            clientAuthentication.primary.asymmetric = {
                asymmetric_key_id: client['asymmetric-key'],
            };

        } else if (client['credential-manager']) {

            clientAuthentication.primary.credential_manager = {
                credential_manager_id: client['credential-manager'],
            };

        } else if (client['mutual-tls']) {

        } else if (client['mutual-tls-by-proxy']) {

        } else if (client['secret']) {

            clientAuthentication.primary.secret = {
                secret: client['secret'],
            };

        } else if (client['symmetric-key']) {

            clientAuthentication.primary.symmetric = {
                symmetric_key: client['symmetric-key'],
            };
        }

        databaseClient.client_authentication = clientAuthentication;
    }

    private setIdToken(databaseClient: DatabaseClient, client: Client): void {

        const idTokenTtl = client['id-token-ttl'];
        if (idTokenTtl) {

            databaseClient.id_token = {
                id_token_ttl: idTokenTtl,
                id_token_encryption: null,
            }
        } 
    }

    private setRefreshToken(databaseClient: DatabaseClient, client: Client): void {

        const refreshTokenTtl = this.getNumberSafe(client['refresh-token-ttl']);
        const refreshTokenMaxRollingLifetime = this.getNumberSafe(client['refresh-token-max-rolling-lifetime']);
        const reuseRefreshTokens = client['reuse-refresh-tokens'];

        if (refreshTokenTtl || refreshTokenMaxRollingLifetime || reuseRefreshTokens)  {

            databaseClient.refresh_token = {
                refresh_token_max_rolling_lifetime: null,
                refresh_token_ttl: 0,
                reuse_refresh_tokens: null,
            }

            if (refreshTokenTtl) {
                databaseClient.refresh_token.refresh_token_ttl = refreshTokenTtl;
            }
            if (refreshTokenMaxRollingLifetime) {
                databaseClient.refresh_token.refresh_token_max_rolling_lifetime = refreshTokenMaxRollingLifetime;
            }
            if (reuseRefreshTokens) {
                databaseClient.refresh_token.reuse_refresh_tokens = reuseRefreshTokens;
            }
        }
    }

    private setUserAuthentication(databaseClient: DatabaseClient, client: Client): void {

        databaseClient.user_authentication = {
            allowed_authenticators: [],
            allowed_post_logout_redirect_uris: [],
            authenticator_filters: [],
            backchannel_logout_uri: null,
            consent: null,
            context_info: '',
            force_authentication: null,
            freshness: null,
            frontchannel_logout_uri: null,
            http_client_id: null,
            locale: null,
            required_claims: [],
            template_area: null,
        };

        /*{
            allowed_authenticators: string[];
            allowed_post_logout_redirect_uris: string[];
            authenticator_filters: string[];
            backchannel_logout_uri: string | null;
            consent: ConsentInput | null;
            context_info: string;
            force_authentication: boolean | null;
            freshness: number | null;
            frontchannel_logout_uri: string | null;
            http_client_id: string | null;
            locale: string | null;
            required_claims: string[];
            template_area: string | null;
        }*/
    }

    private getNumberSafe(value: number | 'disabled' | undefined): number | undefined {
        return value === 'disabled' ? undefined : value;
    }
}

