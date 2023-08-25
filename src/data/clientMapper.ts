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
    CapabilitiesInput,
    ClientAuthenticationInput,
    ClientAuthenticationVerifierInput,
    ClientCredentials,
    Code,
    CreateDatabaseClientInput, 
    DatabaseClientStatus,
    Disable,
    Haapi,
    IdTokenInput,
    Implicit,
    Introspection,
    Ios,
    JwtSigningInput,
    MutualTlsInput,
    NoAuth,
    RefreshTokenInput,
    RequestObjectInput,
    ResourceOwnerPasswordCredentials,
    SubjectType,
    TokenExchange,
    UserAuthenticationInput,
    Web} from './databaseClient.js';

export class ClientMapper {

    public convertToDatabaseClient(configClient: ConfigurationClient): CreateDatabaseClientInput {

        const databaseClient: CreateDatabaseClientInput = {
            fields: {
                access_token_ttl: configClient['access-token-ttl'] || null,
                allow_per_request_redirect_uris: configClient.capabilities?.code?.['require-pushed-authorization-requests']?.['allow-per-request-redirect-uris'] || null,
                allowed_origins: configClient['allowed-origins'] || null,
                application_url: configClient['application-url'] || null,
                audiences: configClient['audience'] || [],
                capabilities: this.getCapabilities(configClient),
                claim_mapper_id: configClient['claims-mapper'] || null,
                client_authentication: this.getClientAuthentication(configClient),
                client_id: configClient['id'],
                description: configClient['description'] || null,
                id_token: this.getIdToken(configClient),
                logo_uri: configClient['logo'] || null,
                name: configClient['client-name'] || '',
                policy_uri: configClient['privacy-policy-url'] || null,
                properties: this.getProperties(configClient),
                redirect_uri_validation_policy_id: configClient['redirect-uri-validation-policy'] || null,
                redirect_uris: configClient['redirect-uris'] || null,
                refresh_token: this.getRefreshToken(configClient),
                request_object: this.getRequestObject(configClient),
                require_secured_authorization_response: Array.isArray(configClient['require-secured-authorization-response']) ? true : false,
                scopes: configClient['scope'] || [],
                sector_identifier: configClient['use-pairwise-subject-identifiers'] ? configClient['use-pairwise-subject-identifiers']?.['sector-identifier'] || null : null,
                status: configClient['enabled'] === false ? new EnumType(DatabaseClientStatus.Inactive) as any : new EnumType(DatabaseClientStatus.Active) as any,
                subject_type: configClient['use-pairwise-subject-identifiers'] ? new EnumType(SubjectType.Pairwise) as any : new EnumType(SubjectType.Public) as any,
                tags: [],
                user_authentication: this.getUserAuthentication(configClient),
                userinfo_signed_issuer_id: configClient['signed-userinfo']?.['userinfo-token-issuer'] || null,
                tos_uri: configClient['terms-of-service-url'] || null,
                validate_port_on_loopback_interfaces: configClient['validate-port-on-loopback-interfaces'] || null,
            }
        };
        
        return databaseClient;
    }

    private getCapabilities(configClient: ConfigurationClient): CapabilitiesInput {

        let capabilities: CapabilitiesInput = {};

        if (configClient.capabilities.assertion) {

            capabilities.assertion = {
                type: new EnumType(Assertion.Assertion) as any,
                jwt: {
                    allow_reuse: configClient.capabilities.assertion?.jwt['allow-reuse'] || false,
                    issuer: configClient.capabilities.assertion?.jwt?.trust?.issuer || null,
                    signing: this.getAssertionSigning(configClient),
                },
            };
        }

        if (configClient.capabilities['assisted-token']) {

            capabilities.assisted_token = {
                type: new EnumType(AssistedToken.AssistedToken) as any,
            };
        }

        if (configClient.capabilities['backchannel-authentication']) {

            capabilities.backchannel = {
                type: new EnumType(BackchannelAuthentication.BackchannelAuthentication) as any,
                allowed_backchannel_authenticators: configClient.capabilities['backchannel-authentication']?.['allowed-authenticators'] || [],
            };
        }

        if (configClient.capabilities['client-credentials']) {

            capabilities.client_credentials = {
                type: ClientCredentials.ClientCredentials,
            }
        }

        if (configClient.capabilities.code) {

            capabilities.code = {
                type: new EnumType(Code.Code) as any, 
                require_pushed_authorization_request: null,
                proof_key: null,
                
            };

            const usePAR = configClient.capabilities.code['require-pushed-authorization-requests']
            if (usePAR) {
                capabilities.code.require_pushed_authorization_request = usePAR ? true : false;
            }

            const proofKey = configClient['proof-key'];
            if (proofKey) {

                const disallowPlain = !!proofKey['disallowed-proof-key-challenge-methods']?.find((m) => m === 'plain');
                const disallowS256 = !!proofKey['disallowed-proof-key-challenge-methods']?.find((m) => m === 'S256');
                capabilities.code.proof_key = {
                    disallow_challenge_method_plain: disallowPlain,
                    disallow_challenge_method_s256: disallowS256,                
                    require_proof_key: proofKey['require-proof-key'],
                };
            }
        }

        if (configClient.capabilities.haapi) {

            capabilities.haapi = {
                type: new EnumType(Haapi.Haapi) as any,
                client_attestation: {} as any,
                use_legacy_dpop: configClient.capabilities.haapi['use-legacy-dpop'] || false,
            };

            if (configClient.attestation) {

                capabilities.haapi.client_attestation = {};
                if (configClient.attestation.android) {

                    capabilities.haapi.client_attestation.android = {
                        type: new EnumType(Android.Android) as any,
                        policy_id: configClient.attestation?.android?.['android-policy'] || null,
                        package_names: configClient.attestation?.android?.['package-name'] || [],
                        signature_fingerprints: configClient.attestation?.android?.['signature-digest'] || [],
                    };

                } else if (configClient.attestation.ios) {

                    capabilities.haapi.client_attestation.ios = {
                        type: new EnumType(Ios.Ios) as any,
                        app_id: configClient.attestation.ios['app-id'],
                        policy_id: configClient.attestation.ios?.['ios-policy'] || null,
                    };

                } else if (configClient.attestation.web) {
                    
                    capabilities.haapi.client_attestation.web = {
                        type: new EnumType(Web.Web) as any,
                        policy_id: configClient.attestation.web?.['web-policy'] || null,
                    };

                } else {

                    capabilities.haapi.client_attestation.no_attestation = {
                        type: new EnumType(Disable.Disable) as any,
                    };
                }
            }
        }

        if (configClient.capabilities.implicit) {

            capabilities.implicit = {
                type: new EnumType(Implicit.Implicit) as any,
            }
        }

        if (configClient.capabilities.introspection) {
            capabilities.introspection = {
                type: new EnumType(Introspection.Introspection) as any,
            }
        }

        if (configClient.capabilities['resource-owner-password-credentials']) {

            capabilities.resource_owner_password = {
                type:  new EnumType(ResourceOwnerPasswordCredentials.Ropc) as any,
                credential_manager_id: configClient.capabilities['resource-owner-password-credentials']?.['credential-manager'] || null,
            };
        }

        if (configClient.capabilities['token-exchange']) {

            capabilities.token_exchange = {
                type: new EnumType(TokenExchange.TokenExchange) as any,
            };
        }

        return capabilities;
    }

    private getClientAuthentication(configClient: ConfigurationClient): ClientAuthenticationInput {

        const secondary = configClient['secondary-authentication-method']
        return {
            primary: this.getPrimaryClientAuthentication(configClient),
            secondary: this.getSecondaryClientAuthentication(configClient),
            secondary_verifier_expiration: secondary?.['expires-on'] ? Date.parse(secondary['expires-on']) / 1000.0 : null,
        };
    }

    private getPrimaryClientAuthentication(configClient: ConfigurationClient): ClientAuthenticationVerifierInput {

        if (configClient['asymmetric-key']) {

            return {
                asymmetric: {
                    asymmetric_key_id: configClient['asymmetric-key'],
                },
            };

        } else if (configClient['credential-manager']) {

            return {
                credential_manager: {
                    credential_manager_id: configClient['credential-manager'],
                },
            };

        } else if (configClient['mutual-tls']) {

            return {
                mutual_tls: this.getMutualTls(configClient['mutual-tls']),
            };

        } else if (configClient['mutual-tls-by-proxy']) {

            return {
                mutual_tls_by_proxy: this.getMutualTls(configClient['mutual-tls-by-proxy']),
            };

        } else if (configClient['secret']) {

            return {
                secret: {
                    secret: configClient['secret'],
                },
            };

        } else if (configClient['symmetric-key']) {

            return {
                symmetric: {
                    symmetric_key: configClient['symmetric-key'],
                },
            };

        } else {

            // JWKS URI is unsupported for database clients, and is migrated with a type of no-authentication
            return {
                no_authentication: new EnumType(NoAuth.NoAuth) as any,
            };
        }
    }

    private getSecondaryClientAuthentication(configClient: ConfigurationClient): ClientAuthenticationVerifierInput | null {

        // No authentication cannot be used for the secondary method, so do not set secondary details if JWKS URI is configured
        const secondary = configClient['secondary-authentication-method']
        if (secondary && !secondary['jwks-uri'] && !secondary['no-authentication']) {

            if (secondary['asymmetric-key']) {

                return {
                    asymmetric: {
                        asymmetric_key_id: secondary['asymmetric-key'],
                    },
                };
    
            } else if (secondary['credential-manager']) {
    
                return {
                    credential_manager: {
                        credential_manager_id: secondary['credential-manager'],
                    },
                };
    
            } else if (secondary['mutual-tls']) {
    
                return {
                    mutual_tls: this.getMutualTls(secondary['mutual-tls']),
                };
    
            } else if (secondary['mutual-tls-by-proxy']) {

                return {
                    mutual_tls_by_proxy: this.getMutualTls(secondary['mutual-tls-by-proxy']),
                };
    
            } else if (secondary['secret']) {
    
                return {
                    secret: {
                        secret: secondary['secret'],
                    },
                };
    
            } else if (secondary['symmetric-key']) {
    
                return {
                    symmetric: {
                        symmetric_key: secondary['symmetric-key'],
                    },
                };
            }
        }
        return null;
    }


    private getMutualTls(configClient: ConfigClientMutualTls): MutualTlsInput {

        const trustedCas = configClient['trusted-ca'] ? [configClient['trusted-ca']] : [];

        if (configClient['client-dn']) {

            return {
                dn: {
                    client_dn: configClient['client-dn'],
                    rdns_to_match: [], // TOFIX
                    trusted_cas: trustedCas,
                },
            };

        } else if (configClient['client-dns-name']) {

            return {
                dns: {
                    client_dns: configClient['client-dns-name'],
                    trusted_cas: trustedCas,
                },
            }

        }  else if (configClient['client-uri']) {

            return {
                uri: {
                    client_uri: configClient['client-uri'],
                    trusted_cas: trustedCas,
                },
            }

        } else if (configClient['client-ip']) {

            return {
                ip: {
                    client_ip: configClient['client-ip'],
                    trusted_cas: trustedCas,
                },
            }

        } else if (configClient['client-email']) {

            return {
                email: {
                    client_email: configClient['client-email'],
                    trusted_cas: trustedCas,
                },
            }

        } else if (configClient['client-certificate']) {

            return {
                pinned_certificate: {
                    client_certificate_id: configClient['client-certificate'],
                },
            };

        } else {

            return {
                trusted_cas: trustedCas,
            }
        }
    }

    private getAssertionSigning(configClient: ConfigurationClient): JwtSigningInput {

        if (configClient.capabilities.assertion?.jwt?.trust?.['asymmetric-signing-key']) {

            return {
                asymmetric_key: {
                    asymmetric_key_id: configClient.capabilities.assertion?.jwt?.trust?.['asymmetric-signing-key'] || '',
                },
            };

        } else if (configClient.capabilities.assertion?.jwt.trust['jwks-uri']) {

            return {
                jwks: {
                    http_client_id: configClient.capabilities.assertion?.jwt.trust['jwks-uri']?.['http-client'] || null,
                    uri: configClient.capabilities.assertion?.jwt.trust['jwks-uri']?.uri,
                },
            };

        } else {

            return {
                symmetric_key: {
                    symmetric_key: configClient['symmetric-key'] || '',
                },
            }
        }
    }

    private getIdToken(configClient: ConfigurationClient): IdTokenInput | null {

        const idTokenTtl = configClient['id-token-ttl'];
        const idTokenEncryption = configClient['id-token-encryption'];
        if (!idTokenTtl && !idTokenEncryption) {
            return null;
        }

        let idToken: IdTokenInput = {};
        if (idTokenTtl) {
            idToken.id_token_ttl = idTokenTtl;
        }
        if (idTokenEncryption?.['content-encryption-algorithm'] &&
            idTokenEncryption?.['key-management-algorithm'] &&
            idTokenEncryption?.['encryption-key']) {

            idToken.id_token_encryption = {
                allowed_content_encryption_alg: idTokenEncryption['content-encryption-algorithm'],
                allowed_key_management_alg: idTokenEncryption['key-management-algorithm'],
                encryption_key_id: idTokenEncryption['encryption-key'],
            };
        }

        return idToken;
    }

    private getRefreshToken(configClient: ConfigurationClient): RefreshTokenInput | null {

        const refreshTokenTtl = this.getNumberAndHandleDisabled(configClient['refresh-token-ttl']);
        const refreshTokenMaxRollingLifetime = this.getNumberAndHandleDisabled(configClient['refresh-token-max-rolling-lifetime']);
        const reuseRefreshTokens = configClient['reuse-refresh-tokens'];

        if (!refreshTokenTtl && !refreshTokenMaxRollingLifetime && !reuseRefreshTokens)  {
            return null;
        }

        const refreshToken: RefreshTokenInput = {
            refresh_token_max_rolling_lifetime: null,
            refresh_token_ttl: 0,
            reuse_refresh_tokens: null,
        }

        if (refreshTokenTtl) {
            refreshToken.refresh_token_ttl = refreshTokenTtl;
        }
        if (refreshTokenMaxRollingLifetime) {
            refreshToken.refresh_token_max_rolling_lifetime = refreshTokenMaxRollingLifetime;
        }
        if (reuseRefreshTokens) {
            refreshToken.reuse_refresh_tokens = reuseRefreshTokens;
        }

        return refreshToken;
    }

    private getNumberAndHandleDisabled(value: number | 'disabled' | undefined): number | undefined {
        return value === 'disabled' ? undefined : value;
    }

    private getProperties(configClient: ConfigurationClient): any {

        const properties: any = {};

        configClient['properties']?.property.forEach((p) => {
            properties[p.key] = p.value;
        });

        return properties;
    }

    private getRequestObject(configClient: ConfigurationClient): RequestObjectInput | null {

        const source = configClient['request-object'];
        if (!source) {
            return null;
        }

        let requestObject: RequestObjectInput = {
            allow_unsigned_for_by_value: source['allow-unsigned-for-by-value'],
            by_reference: null,
            request_jwt_issuer: source['issuer'] || null,
            request_jwt_signature_verification_key: source['signature-verification-key'] || null,
        }

        const sourceByRef = source['by-reference'];
        if (sourceByRef) {
            requestObject.by_reference = {
                allow_unsigned_for: sourceByRef['allow-unsigned'] || null,
                allowed_request_urls: sourceByRef['allowed-request-url'] || [],
                http_client_id: sourceByRef['http-client'] || null,
            };
        }

        return requestObject;
    }

    private getUserAuthentication(configClient: ConfigurationClient): UserAuthenticationInput | null {

        const source = configClient['user-authentication'];
        if (!source) {
            return null;
        }
            
        const userAuthentication: UserAuthenticationInput = {
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

            userAuthentication.consent = {
                allow_deselection: consent['allow-deselection'],
                only_consentors: consent['only-consentors'],
                consentors: consent.consentors?.consentor || [],
            }
        }

        return userAuthentication;
    }
}
