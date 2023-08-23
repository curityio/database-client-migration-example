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

import {EnumType} from 'json-to-graphql-query';
import {Client, MutualTls} from './clients.js';

import {
    Android,
    Assertion,
    AssistedToken,
    BackchannelAuthentication,
    ClientCredentials,
    Code,
    DatabaseClient, 
    DatabaseClientHaapi,
    Implicit,
    Introspection,
    Ios,
    MutualTlsInput,
    NoAuth,
    ResourceOwnerPasswordCredentials,
    TokenExchange,
    Web} from './database-clients.js';

export class ClientMapper {

    public convertToDatabaseClient(client: Client): DatabaseClient {

        // Set easily derivable values, with placeholders for more complex objects such as capabilities
        const databaseClient: DatabaseClient = {
            access_token_ttl: client['access-token-ttl'] || null,
            allow_per_request_redirect_uris: client.capabilities?.code?.['require-pushed-authorization-requests']?.['allow-per-request-redirect-uris'] || null,
            allowed_origins: client['allowed-origins'] || null,
            application_url: client['application-url'] || null,
            audiences: client['audience'] || [],
            capabilities: {} as any,
            claim_mapper_id: client['claims-mapper'] || null,
            client_authentication: {} as any,
            client_id: client['id'],
            description: client['description'] || null,
            id_token: null,
            logo_uri: client['logo'] || null,
            name: client['client-name'] || null,
            policy_uri: client['privacy-policy-url'] || null,
            properties: {},
            redirect_uri_validation_policy_id: client['redirect-uri-validation-policy'] || null,
            redirect_uris: client['redirect-uris'] || null,
            refresh_token: null,
            request_object: null,
            require_secured_authorization_response: Array.isArray(client['require-secured-authorization-response']) ? true : false,
            scopes: client['scope'] || [],
            sector_identifier: null,
            status: client['enabled'] ? 'ACTIVE' : 'INACTIVE',
            subject_type: 'public',
            tags: [],
            user_authentication: null,
            userinfo_signed_issuer_id: client['signed-userinfo']?.['userinfo-token-issuer'] || null,
            tos_uri: client['terms-of-service-url'] || null,
            validate_port_on_loopback_interfaces: client['validate-port-on-loopback-interfaces'] || null,
        };

        // Apply any logic to update any placeholders from above
        this.setCapabilities(databaseClient, client);
        this.setClientAuthentication(databaseClient, client);
        this.setIdToken(databaseClient, client);
        this.setPPIDs(databaseClient, client);
        this.setProperties(databaseClient, client);
        this.setRefreshToken(databaseClient, client);
        this.setRequestObject(databaseClient, client);
        this.setUserAuthentication(databaseClient, client);

        // Handle enumerated types specially, so that we can correctly produce the GraphQL string to post later
        (databaseClient as any).status = new EnumType(databaseClient.status),
        (databaseClient as any).subject_type = new EnumType(databaseClient.subject_type)

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

        if (client.capabilities.assertion) {

            const jwksUri = client.capabilities.assertion?.jwt.trust['jwks-uri']?.uri;

            databaseClient.capabilities.assertion = {
                type: new EnumType(Assertion.ASSERTION) as any,
                jwt: {
                    allow_reuse: client.capabilities.assertion?.jwt['allow-reuse'] || false,
                    issuer: client.capabilities.assertion?.jwt?.trust?.issuer || null,
                    signing: {
                        asymmetric_key_id: client.capabilities.assertion?.jwt?.trust?.['asymmetric-signing-key'],
                        symmetric_key: undefined,
                        jwks: jwksUri ? {
                            http_client_id: client.capabilities.assertion?.jwt.trust['jwks-uri']?.['http-client'] || null,
                            uri: jwksUri,
                        } : undefined,
                    }
                },
            };
        }

        if (client.capabilities['assisted-token']) {

            databaseClient.capabilities.assisted_token = {
                type: new EnumType(AssistedToken.ASSISTED_TOKEN) as any,
            };
        }

        if (client.capabilities['backchannel-authentication']) {

            databaseClient.capabilities.backchannel = {
                type: new EnumType(BackchannelAuthentication.BACKCHANNEL_AUTHENTICATION) as any,
                allowed_backchannel_authenticators: client.capabilities['backchannel-authentication']?.['allowed-authenticators'] || [],
            };
        }

        if (client.capabilities['client-credentials']) {

            databaseClient.capabilities.client_credentials = {
                type: new EnumType(ClientCredentials.CLIENT_CREDENTIALS) as any,
            }
        }

        if (client.capabilities.code) {

            databaseClient.capabilities.code = {
                type: new EnumType(Code.CODE) as any, 
                require_pushed_authorization_request: null,
                proof_key: null,
                
            };

            const usePAR = client.capabilities.code['require-pushed-authorization-requests']
            if (usePAR) {
                databaseClient.capabilities.code.require_pushed_authorization_request = usePAR ? true : false;
            }

            const proofKey = client['proof-key'];
            if (proofKey) {

                const disallowPlain = !!proofKey['disallowed-proof-key-challenge-methods']?.find((m) => m === 'plain');
                const disallowS256 = !!proofKey['disallowed-proof-key-challenge-methods']?.find((m) => m === 'S256');
                databaseClient.capabilities.code.proof_key = {
                    disallow_challenge_method_plain: disallowPlain,
                    disallow_challenge_method_s256: disallowS256,                
                    require_proof_key: proofKey['require-proof-key'],
                };
            }
        }

        if (client.capabilities.haapi) {

            databaseClient.capabilities.haapi = {
                type: new EnumType(DatabaseClientHaapi.HAAPI) as any,
                client_attestation: {} as any,
                use_legacy_dpop: client.capabilities.haapi['use-legacy-dpop'] || false,
            };

            if (client.attestation) {

                databaseClient.capabilities.haapi.client_attestation = {};

                if (client.attestation['attestation-type'] === 'web') {
                    
                    databaseClient.capabilities.haapi.client_attestation.web = {
                        type: Web.WEB,
                        policy_id: client.attestation.web?.['web-policy'] || null,
                    };
                    (databaseClient.capabilities.haapi.client_attestation.web as any).type = new EnumType(databaseClient.capabilities.haapi.client_attestation.web.type);

                } else if (client.attestation['attestation-type'] === 'android') {

                    databaseClient.capabilities.haapi.client_attestation.android = {
                        type: Android.ANDROID,
                        policy_id: client.attestation?.android?.['android-policy'] || null,
                        package_names: client.attestation?.android?.['package-name'] || [],
                        signature_fingerprints: client.attestation?.android?.['signature-digest'] || [],
                    };
                    (databaseClient.capabilities.haapi.client_attestation.android as any).type = new EnumType(databaseClient.capabilities.haapi.client_attestation.android.type);

                } else if (client.attestation['attestation-type'] === 'ios' && client.attestation.ios?.['app-id']) {

                    databaseClient.capabilities.haapi.client_attestation.ios = {
                        type: Ios.IOS,
                        app_id: client.attestation.ios['app-id'],
                        policy_id: client.attestation.ios?.['ios-policy'] || null,
                    };
                    (databaseClient.capabilities.haapi.client_attestation.ios as any).type = new EnumType(databaseClient.capabilities.haapi.client_attestation.ios.type);
                }
            }
        }

        if (client.capabilities.implicit) {

            databaseClient.capabilities.implicit = {
                type: new EnumType(Implicit.IMPLICIT) as any,
            }
        }

        if (client.capabilities.introspection) {
            databaseClient.capabilities.introspection = {
                type: new EnumType(Introspection.INTROSPECTION) as any,
            }
        }

        if (client.capabilities['resource-owner-password-credentials']) {

            databaseClient.capabilities.resource_owner_password = {
                type: new EnumType(ResourceOwnerPasswordCredentials.ROPC) as any,
                credential_manager_id: client.capabilities['resource-owner-password-credentials']?.['credential-manager'] || null,
            };
        }

        if (client.capabilities['token-exchange']) {

            databaseClient.capabilities.token_exchange = {
                type: new EnumType(TokenExchange.TOKEN_EXCHANGE) as any,
            };
        }
    }

    private setClientAuthentication(databaseClient: DatabaseClient, client: Client): void {

        databaseClient.client_authentication = {
            primary: {},
            secondary: null,
            secondary_verifier_expiration: null,
        };

        if (client['asymmetric-key']) {

            databaseClient.client_authentication.primary.asymmetric = {
                asymmetric_key_id: client['asymmetric-key'],
            };

        } else if (client['credential-manager']) {

            databaseClient.client_authentication.primary.credential_manager = {
                credential_manager_id: client['credential-manager'],
            };

        } else if (client['mutual-tls']) {

            databaseClient.client_authentication.primary.mutual_tls = {};
            this.setMutualTlsDetails(client['mutual-tls'], databaseClient.client_authentication.primary.mutual_tls);

        } else if (client['mutual-tls-by-proxy']) {

            databaseClient.client_authentication.primary.mutual_tls_by_proxy = {};
            this.setMutualTlsDetails(client['mutual-tls-by-proxy'], databaseClient.client_authentication.primary.mutual_tls_by_proxy);

        } else if (client['secret']) {

            databaseClient.client_authentication.primary.secret = {
                secret: client['secret'],
            };

        } else if (client['symmetric-key']) {

            databaseClient.client_authentication.primary.symmetric = {
                symmetric_key: client['symmetric-key'],
            };

        } else {

            // JWKS URI is unsupported for database clients, and is migrated with a type of no-authentication
            databaseClient.client_authentication.primary.no_authentication = NoAuth.no_auth;
        }

        const secondary = client['secondary-authentication-method']
        if (secondary) {

            if (secondary['expires-on']) {
                databaseClient.client_authentication.secondary_verifier_expiration = Date.parse(secondary['expires-on']) / 1000.0;
            }

            databaseClient.client_authentication.secondary = {};

            if (secondary['asymmetric-key']) {

                databaseClient.client_authentication.secondary.asymmetric = {
                    asymmetric_key_id: secondary['asymmetric-key'],
                };
    
            } else if (secondary['credential-manager']) {
    
                databaseClient.client_authentication.secondary.credential_manager = {
                    credential_manager_id: secondary['credential-manager'],
                };
    
            } else if (secondary['mutual-tls']) {
    
                databaseClient.client_authentication.secondary.mutual_tls = {};
                this.setMutualTlsDetails(secondary['mutual-tls'], databaseClient.client_authentication.secondary.mutual_tls)
    
            } else if (secondary['mutual-tls-by-proxy']) {
    
                databaseClient.client_authentication.secondary.mutual_tls_by_proxy = {};
                this.setMutualTlsDetails(secondary['mutual-tls-by-proxy'], databaseClient.client_authentication.secondary.mutual_tls_by_proxy);
    
            } else if (secondary['secret']) {
    
                databaseClient.client_authentication.secondary.secret = {
                    secret: secondary['secret'],
                };
    
            } else if (secondary['symmetric-key']) {
    
                databaseClient.client_authentication.secondary.symmetric = {
                    symmetric_key: secondary['symmetric-key'],
                };
    
            } else {
    
                // JWKS URI is unsupported for database clients, and is migrated with a type of no-authentication
                databaseClient.client_authentication.secondary.no_authentication = NoAuth.no_auth;
            }
        }
    }

    private setIdToken(databaseClient: DatabaseClient, client: Client): void {

        const idTokenTtl = client['id-token-ttl'];
        const idTokenEncryption = client['id-token-encryption'];
        if (idTokenTtl || idTokenEncryption) {

            databaseClient.id_token = {
                id_token_ttl: null,
                id_token_encryption: null,
            };

            if (idTokenTtl) {
                databaseClient.id_token.id_token_ttl = idTokenTtl;
            }
            if (idTokenEncryption?.['content-encryption-algorithm'] &&
                idTokenEncryption?.['key-management-algorithm'] &&
                idTokenEncryption?.['encryption-key']) {

                databaseClient.id_token.id_token_encryption = {
                    allowed_content_encryption_alg: idTokenEncryption['content-encryption-algorithm'],
                    allowed_key_management_alg: idTokenEncryption['key-management-algorithm'],
                    encryption_key_id: idTokenEncryption['encryption-key'],
                };
            }
        }
    }

    private setPPIDs(databaseClient: DatabaseClient, client: Client): void {

        const usePPIDs = client['use-pairwise-subject-identifiers'];
        if (usePPIDs) {
            databaseClient.subject_type = 'pairwise';
            databaseClient.sector_identifier = usePPIDs['sector-identifier'] || null;
        }
    }

    private setProperties(databaseClient: DatabaseClient, client: Client): void {

        client['properties']?.property.forEach((p) => {
            databaseClient.properties[p.key] = p.value;
        });
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

    private setRequestObject(databaseClient: DatabaseClient, client: Client): void {

        const source = client['request-object'];
        if (source) {

            databaseClient.request_object = {
                allow_unsigned_for_by_value: source['allow-unsigned-for-by-value'],
                by_reference: null,
                request_jwt_issuer: source['issuer'] || null,
                request_jwt_signature_verification_key: source['signature-verification-key'] || null,
            }

            const sourceByRef = source['by-reference'];
            if (sourceByRef) {
                databaseClient.request_object.by_reference = {
                    allow_unsigned_for: sourceByRef['allow-unsigned'] || null,
                    allowed_request_urls: sourceByRef['allowed-request-url'] || [],
                    http_client_id: sourceByRef['http-client'] || null,
                };
            }
        }
    }

    private setUserAuthentication(databaseClient: DatabaseClient, client: Client): void {

        const source = client['user-authentication'];
        if (source) {
            
            databaseClient.user_authentication = {
                allowed_authenticators: source['allowed-authenticators'] || [],
                allowed_post_logout_redirect_uris: source['allowed-post-logout-redirect-uris'] || [],
                authenticator_filters: source['authenticator-filters'] || [],
                backchannel_logout_uri: source['backchannel-logout-uri'] || null,
                consent: null,
                context_info: source['context-info'] || '',
                force_authentication: source['force-authn'] || null,
                freshness: source.freshness || null,
                frontchannel_logout_uri: source['frontchannel-logout-uri'] || null,
                http_client_id: source['http-client'] || null,
                locale: source.locale || null,
                required_claims: source['required-claims'] || [],
                template_area: source['template-area'] || null,
            };

            const consent = client['user-consent'];
            if (consent) {

                databaseClient.user_authentication.consent = {
                    allow_deselection: consent['allow-deselection'] || null,
                    only_consentors: consent['only-consentors'] || null,
                    consentors: consent.consentors?.consentor || [],
                }
            }
        }
    }

    private setMutualTlsDetails(source: MutualTls, destination: MutualTlsInput) {

        const trustedCas = source['trusted-ca'] ? [source['trusted-ca']] : [];

        if (source['client-certificate']) {
            destination.pinned_certificate = {
                client_certificate_id: source['client-certificate'],
            }
            
            destination.trusted_cas = trustedCas;
        }

        if (source['client-dn']) {

            destination.dn = {
                client_dn: source['client-dn'],
                trusted_cas: trustedCas,
                rdns_to_match: [],
            }

        } else if (source['client-dns-name']) {

            destination.dns = {
                client_dns: source['client-dns-name'],
                trusted_cas: trustedCas,
            }

        }  else if (source['client-uri']) {

            destination.uri = {
                client_uri: source['client-uri'],
                trusted_cas: trustedCas,
            }

        } else if (source['client-ip']) {

            destination.ip = {
                client_ip: source['client-ip'],
                trusted_cas: trustedCas,
            }

        } else if (source['client-email']) {

            destination.email = {
                client_email: source['client-email'],
                trusted_cas: trustedCas,
            }
        }
    }

    private getNumberSafe(value: number | 'disabled' | undefined): number | undefined {
        return value === 'disabled' ? undefined : value;
    }
}
