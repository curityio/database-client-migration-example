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
import {ConfigurationClient, MutualTls as ConfigClientMutualTls} from './configurationClient.js';

import {
    Android,
    Assertion,
    AssistedToken,
    BackchannelAuthentication,
    ClientCredentials,
    Code,
    DatabaseClient, 
    DatabaseClientStatus,
    Disable,
    Haapi,
    Implicit,
    Introspection,
    Ios,
    JwtSigning,
    MutualTls,
    NoAuth,
    ResourceOwnerPasswordCredentials,
    SubjectType,
    TokenExchange,
    Web} from './databaseClient.js';

export class ClientMapper {

    public convertToDatabaseClient(owner: string, configClient: ConfigurationClient): DatabaseClient {

        // Set easily derivable values, with placeholders for more complex objects such as capabilities
        const databaseClient: DatabaseClient = {
            access_token_ttl: configClient['access-token-ttl'] || null,
            allow_per_request_redirect_uris: configClient.capabilities?.code?.['require-pushed-authorization-requests']?.['allow-per-request-redirect-uris'] || null,
            allowed_origins: configClient['allowed-origins'] || null,
            application_url: configClient['application-url'] || null,
            audiences: configClient['audience'] || [],
            capabilities: {} as any,
            claim_mapper_id: configClient['claims-mapper'] || null,
            client_authentication: {} as any,
            client_id: configClient['id'],
            description: configClient['description'] || null,
            id_token: null,
            logo_uri: configClient['logo'] || null,
            name: configClient['client-name'] || '',
            owner,
            policy_uri: configClient['privacy-policy-url'] || null,
            properties: {},
            redirect_uri_validation_policy_id: configClient['redirect-uri-validation-policy'] || null,
            redirect_uris: configClient['redirect-uris'] || null,
            refresh_token: null,
            request_object: null,
            require_secured_authorization_response: Array.isArray(configClient['require-secured-authorization-response']) ? true : false,
            scopes: configClient['scope'] || [],
            sector_identifier: null,
            status: configClient['enabled'] === false ? new EnumType(DatabaseClientStatus.Inactive) as any : new EnumType(DatabaseClientStatus.Active) as any,
            subject_type: new EnumType(SubjectType.Public) as any,
            tags: [],
            user_authentication: null,
            userinfo_signed_issuer_id: configClient['signed-userinfo']?.['userinfo-token-issuer'] || null,
            tos_uri: configClient['terms-of-service-url'] || null,
            validate_port_on_loopback_interfaces: configClient['validate-port-on-loopback-interfaces'] || null,
        };

        // Apply any logic to update placeholders, for more complex translations
        this.setCapabilities(databaseClient, configClient);
        this.setClientAuthentication(databaseClient, configClient);
        this.setIdToken(databaseClient, configClient);
        this.setPPIDs(databaseClient, configClient);
        this.setProperties(databaseClient, configClient);
        this.setRefreshToken(databaseClient, configClient);
        this.setRequestObject(databaseClient, configClient);
        this.setUserAuthentication(databaseClient, configClient);

        return databaseClient;
    }

    private setCapabilities(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

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

        if (configClient.capabilities.assertion) {

            databaseClient.capabilities.assertion = {
                type: new EnumType(Assertion.Assertion) as any,
                jwt: {
                    allow_reuse: configClient.capabilities.assertion?.jwt['allow-reuse'] || false,
                    issuer: configClient.capabilities.assertion?.jwt?.trust?.issuer || null,
                    signing: this.getAssertionSigning(configClient),
                },
            };
        }

        if (configClient.capabilities['assisted-token']) {

            databaseClient.capabilities.assisted_token = {
                type: new EnumType(AssistedToken.AssistedToken) as any,
            };
        }

        if (configClient.capabilities['backchannel-authentication']) {

            databaseClient.capabilities.backchannel = {
                type: new EnumType(BackchannelAuthentication.BackchannelAuthentication) as any,
                allowed_backchannel_authenticators: configClient.capabilities['backchannel-authentication']?.['allowed-authenticators'] || [],
            };
        }

        if (configClient.capabilities['client-credentials']) {

            databaseClient.capabilities.client_credentials = {
                type: ClientCredentials.ClientCredentials,
            }
        }

        if (configClient.capabilities.code) {

            databaseClient.capabilities.code = {
                type: new EnumType(Code.Code) as any, 
                require_pushed_authorization_request: null,
                proof_key: null,
                
            };

            const usePAR = configClient.capabilities.code['require-pushed-authorization-requests']
            if (usePAR) {
                databaseClient.capabilities.code.require_pushed_authorization_request = usePAR ? true : false;
            }

            const proofKey = configClient['proof-key'];
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

        if (configClient.capabilities.haapi) {

            databaseClient.capabilities.haapi = {
                type: new EnumType(Haapi.Haapi) as any,
                client_attestation: {} as any,
                use_legacy_dpop: configClient.capabilities.haapi['use-legacy-dpop'] || false,
            };

            if (configClient.attestation) {

                if (configClient.attestation.android) {

                    databaseClient.capabilities.haapi.client_attestation = {
                        type: new EnumType(Android.Android) as any,
                        policy_id: configClient.attestation?.android?.['android-policy'] || null,
                        package_names: configClient.attestation?.android?.['package-name'] || [],
                        signature_fingerprints: configClient.attestation?.android?.['signature-digest'] || [],
                    };

                } else if (configClient.attestation.ios) {

                    databaseClient.capabilities.haapi.client_attestation = {
                        type: new EnumType(Ios.Ios) as any,
                        app_id: configClient.attestation.ios['app-id'],
                        policy_id: configClient.attestation.ios?.['ios-policy'] || null,
                    };

                } else if (configClient.attestation.web) {
                    
                    databaseClient.capabilities.haapi.client_attestation = {
                        type: new EnumType(Web.Web) as any,
                        policy_id: configClient.attestation.web?.['web-policy'] || null,
                    };

                } else {

                    databaseClient.capabilities.haapi.client_attestation = {
                        type: new EnumType(Disable.Disable) as any,
                    };
                }
            }
        }

        if (configClient.capabilities.implicit) {

            databaseClient.capabilities.implicit = {
                type: new EnumType(Implicit.Implicit) as any,
            }
        }

        if (configClient.capabilities.introspection) {
            databaseClient.capabilities.introspection = {
                type: new EnumType(Introspection.Introspection) as any,
            }
        }

        if (configClient.capabilities['resource-owner-password-credentials']) {

            databaseClient.capabilities.resource_owner_password = {
                type:  new EnumType(ResourceOwnerPasswordCredentials.Ropc) as any,
                credential_manager_id: configClient.capabilities['resource-owner-password-credentials']?.['credential-manager'] || null,
            };
        }

        if (configClient.capabilities['token-exchange']) {

            databaseClient.capabilities.token_exchange = {
                type: new EnumType(TokenExchange.TokenExchange) as any,
            };
        }
    }

    private setClientAuthentication(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        databaseClient.client_authentication = {
            primary: {} as any,
            secondary: null,
            secondary_verifier_expiration: null,
        };

        if (configClient['asymmetric-key']) {

            databaseClient.client_authentication.primary = {
                asymmetric_key_id: configClient['asymmetric-key'],
            };

        } else if (configClient['credential-manager']) {

            databaseClient.client_authentication.primary = {
                credential_manager_id: configClient['credential-manager'],
            };

        } else if (configClient['mutual-tls']) {

            databaseClient.client_authentication.primary = {
                mutual_tls: this.getMutualTlsDetails(configClient['mutual-tls']),
            }

        } else if (configClient['mutual-tls-by-proxy']) {

            databaseClient.client_authentication.primary = {
                mutual_tls_by_proxy: this.getMutualTlsDetails(configClient['mutual-tls-by-proxy']),
            }

        } else if (configClient['secret']) {

            databaseClient.client_authentication.primary = {
                secret: configClient['secret'],
            };

        } else if (configClient['symmetric-key']) {

            databaseClient.client_authentication.primary = {
                symmetric_key: configClient['symmetric-key'],
            };

        } else {

            // JWKS URI is unsupported for database clients, and is migrated with a type of no-authentication
            databaseClient.client_authentication.primary = {
                no_authentication: NoAuth.NoAuth,
            }
        }

        // No authentication cannot be used for the secondary method, so do not set secondary details if JWKS URI is configured
        const secondary = configClient['secondary-authentication-method']
        if (secondary && !secondary['jwks-uri'] && !secondary['no-authentication']) {

            if (secondary['expires-on']) {
                databaseClient.client_authentication.secondary_verifier_expiration = Date.parse(secondary['expires-on']) / 1000.0;
            }

            if (secondary['asymmetric-key']) {

                databaseClient.client_authentication.secondary = {
                    asymmetric_key_id: secondary['asymmetric-key'],
                };
    
            } else if (secondary['credential-manager']) {
    
                databaseClient.client_authentication.secondary = {
                    credential_manager_id: secondary['credential-manager'],
                };
    
            } else if (secondary['mutual-tls']) {
    
                databaseClient.client_authentication.secondary = {
                    mutual_tls: this.getMutualTlsDetails(secondary['mutual-tls']),
                }
    
            } else if (secondary['mutual-tls-by-proxy']) {
    
                databaseClient.client_authentication.secondary = {
                    mutual_tls_by_proxy:  this.getMutualTlsDetails(secondary['mutual-tls-by-proxy']),
                }
    
            } else if (secondary['secret']) {
    
                databaseClient.client_authentication.secondary = {
                    secret: secondary['secret'],
                };
    
            } else if (secondary['symmetric-key']) {
    
                databaseClient.client_authentication.secondary = {
                    symmetric_key: secondary['symmetric-key'],
                };
            }
        }
    }

    private getAssertionSigning(configClient: ConfigurationClient): JwtSigning {

        if (configClient.capabilities.assertion?.jwt?.trust?.['asymmetric-signing-key']) {

            return {
                asymmetric_key_id: configClient.capabilities.assertion?.jwt?.trust?.['asymmetric-signing-key'] || '',
            };

        } else if (configClient.capabilities.assertion?.jwt.trust['jwks-uri']) {

            return {
                http_client_id: configClient.capabilities.assertion?.jwt.trust['jwks-uri']?.['http-client'] || null,
                uri: configClient.capabilities.assertion?.jwt.trust['jwks-uri']?.uri,
            };

        } else {

            return {
                symmetric_key: configClient['symmetric-key'] || '',
            }
        }
    }

    private setIdToken(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        const idTokenTtl = configClient['id-token-ttl'];
        const idTokenEncryption = configClient['id-token-encryption'];
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

    private setPPIDs(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        const usePPIDs = configClient['use-pairwise-subject-identifiers'];
        if (usePPIDs) {
            databaseClient.subject_type = new EnumType(SubjectType.Pairwise) as any;
            databaseClient.sector_identifier = usePPIDs['sector-identifier'] || null;
        }
    }

    private setProperties(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        configClient['properties']?.property.forEach((p) => {
            databaseClient.properties[p.key] = p.value;
        });
    }

    private setRefreshToken(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        const refreshTokenTtl = this.getNumberSafe(configClient['refresh-token-ttl']);
        const refreshTokenMaxRollingLifetime = this.getNumberSafe(configClient['refresh-token-max-rolling-lifetime']);
        const reuseRefreshTokens = configClient['reuse-refresh-tokens'];

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

    private setRequestObject(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        const source = configClient['request-object'];
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

    private setUserAuthentication(databaseClient: DatabaseClient, configClient: ConfigurationClient): void {

        const source = configClient['user-authentication'];
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

            const consent = configClient['user-consent'];
            if (consent) {

                databaseClient.user_authentication.consent = {
                    allow_deselection: consent['allow-deselection'],
                    only_consentors: consent['only-consentors'],
                    consentors: consent.consentors?.consentor || [],
                }
            }
        }
    }

    private getMutualTlsDetails(source: ConfigClientMutualTls): MutualTls {

        const trustedCas = source['trusted-ca'] ? [source['trusted-ca']] : [];

        if (source['client-dn']) {

            return {
                client_dn: source['client-dn'],
                rdns_to_match: [], // TOFIX
                trusted_cas: trustedCas,
            };

        } else if (source['client-dns-name']) {

            return {
                client_dns: source['client-dns-name'],
                trusted_cas: trustedCas,
            }

        }  else if (source['client-uri']) {

            return {
                client_uri: source['client-uri'],
                trusted_cas: trustedCas,
            }

        } else if (source['client-ip']) {

            return {
                client_ip: source['client-ip'],
                trusted_cas: trustedCas,
            }

        } else if (source['client-email']) {

            return {
                client_email: source['client-email'],
                trusted_cas: trustedCas,
            }

        } else if (source['client-certificate']) {

            return {
                client_certificate_id: source['client-certificate'],
            };

        } else {

            return {
                trusted_cas: trustedCas,
            }
        }
    }

    private getNumberSafe(value: number | 'disabled' | undefined): number | undefined {
        return value === 'disabled' ? undefined : value;
    }
}
