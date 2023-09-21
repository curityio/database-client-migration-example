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

import {
    AsymmetricKeyManagementAlgorithm as ConfigClientAsymmetricKeyManagementAlgorithm,
    ConfigurationClient,
    ContentEncryptionAlgorithm as ConfigClientContentEncryptionAlgorithm} from './configurationClient.js';

import {
    Android,
    Assertion,
    AssistedToken,
    AsymmetricKeyManagementAlgorithm,
    BackchannelAuthentication,
    CapabilitiesInput,
    ClientAuthenticationInput,
    ClientAuthenticationVerifierInput,
    ClientCredentials,
    Code,
    ContentEncryptionAlgorithm,
    CreateDatabaseClientInput, 
    DatabaseClientStatus,
    Disable,
    Haapi,
    IdTokenInput,
    Implicit,
    Introspection,
    Ios,
    JwtSigningInput,
    NoAuth,
    RefreshTokenInput,
    RequestObjectInput,
    ResourceOwnerPasswordCredentials,
    SubjectType,
    TokenExchange,
    UserAuthenticationInput,
    Web} from './databaseClient.js';

export class ClientMapper {

    private migrationTag: string; 

    /*
     * A tag can be written against clients
     */
    public constructor(migrationTag: string) {
        this.migrationTag = migrationTag;
    }

    /*
     * The main mapping algorithm for each client
     */
    public convertToDatabaseClient(configClient: ConfigurationClient): CreateDatabaseClientInput | null {

        if (!this.isSupported(configClient)) {
            return null;
        }

        return {
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
                status: configClient['enabled'] === false ? DatabaseClientStatus.Inactive : DatabaseClientStatus.Active,
                subject_type: configClient['use-pairwise-subject-identifiers'] ? SubjectType.Pairwise : SubjectType.Public,
                tags: [this.migrationTag],
                user_authentication: this.getUserAuthentication(configClient),
                userinfo_signed_issuer_id: configClient['signed-userinfo']?.['userinfo-token-issuer'] || null,
                tos_uri: configClient['terms-of-service-url'] || null,
                validate_port_on_loopback_interfaces: configClient['validate-port-on-loopback-interfaces'] || null,
            }
        };
    }

    private isSupported(configClient: ConfigurationClient): boolean {

        // Clients with these key based authentication methods are not supported as database clients yet
        if (configClient['mutual-tls']          ||
            configClient['mutual-tls-by-proxy'] ||
            configClient['jwks-uri']            || 
            configClient['symmetric-key']) {
            
            return false;
        }

        // They are not supported for secondary authentication either
        const secondary = configClient['secondary-authentication-method'];
        if (secondary) {
            if (secondary['mutual-tls']          ||
                secondary['mutual-tls-by-proxy'] || 
                secondary['jwks-uri']            ||
                secondary['symmetric-key']) {
                
                return false;
            }
        }

        // DCR template clients are not supported as database clients
        if (configClient['dynamic-client-registration-template']) {
            return false;
        }

        return true;
    }

    private getCapabilities(configClient: ConfigurationClient): CapabilitiesInput {

        let capabilities: CapabilitiesInput = {};

        if (configClient.capabilities.assertion) {

            capabilities.assertion = {
                type: Assertion.Assertion,
                jwt: {
                    allow_reuse: configClient.capabilities.assertion?.jwt['allow-reuse'] || false,
                    issuer: configClient.capabilities.assertion?.jwt?.trust?.issuer || null,
                    signing: this.getAssertionSigning(configClient),
                },
            };
        }

        if (configClient.capabilities['assisted-token']) {

            capabilities.assisted_token = {
                type: AssistedToken.AssistedToken,
            };
        }

        if (configClient.capabilities['backchannel-authentication']) {

            capabilities.backchannel = {
                type: BackchannelAuthentication.BackchannelAuthentication,
                allowed_backchannel_authenticators: configClient.capabilities['backchannel-authentication']?.['allowed-authenticators'] || [],
            };
        }

        if (configClient.capabilities['client-credentials']) {

            capabilities.client_credentials = {
                type: ClientCredentials.ClientCredentials,
            };
        }

        if (configClient.capabilities.code) {

            capabilities.code = {
                type: Code.Code, 
                require_pushed_authorization_request: null,
                proof_key: null,
                
            };

            const usePAR = configClient.capabilities.code['require-pushed-authorization-requests']
            if (usePAR) {
                capabilities.code.require_pushed_authorization_request = true;
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
                type: Haapi.Haapi,
                client_attestation: {},
                use_legacy_dpop: configClient.capabilities.haapi['use-legacy-dpop'] || false,
            };

            if (configClient.capabilities.haapi['allow-without-attestation']) {
                capabilities.haapi.client_attestation!.no_attestation = {
                    type: Disable.Disable,
                }
            }

            if (configClient.attestation) {

                
                if (configClient.attestation.android) {

                    capabilities.haapi.client_attestation!.android = {
                        type: Android.Android,
                        policy_id: configClient.attestation?.android?.['android-policy'] || null,
                        package_names: configClient.attestation?.android?.['package-name'] || [],
                        signature_fingerprints: configClient.attestation?.android?.['signature-digest'] || [],
                    };

                } else if (configClient.attestation.ios) {

                    capabilities.haapi.client_attestation!.ios = {
                        type: Ios.Ios,
                        app_id: configClient.attestation.ios['app-id'],
                        policy_id: configClient.attestation.ios?.['ios-policy'] || null,
                    };

                } else if (configClient.attestation.web) {
                    
                    capabilities.haapi.client_attestation!.web = {
                        type: Web.Web,
                        policy_id: configClient.attestation.web?.['web-policy'] || null,
                    };

                } else {

                    capabilities.haapi.client_attestation!.no_attestation = {
                        type: Disable.Disable,
                    };
                }
            }
        }

        if (configClient.capabilities.implicit) {

            capabilities.implicit = {
                type: Implicit.Implicit,
            };
        }

        if (configClient.capabilities.introspection) {

            capabilities.introspection = {
                type: Introspection.Introspection,
            };
        }

        if (configClient.capabilities['resource-owner-password-credentials']) {

            capabilities.resource_owner_password = {
                type:  ResourceOwnerPasswordCredentials.Ropc,
                credential_manager_id: configClient.capabilities['resource-owner-password-credentials']?.['credential-manager'] || null,
            };
        }

        if (configClient.capabilities['token-exchange']) {

            capabilities.token_exchange = {
                type: TokenExchange.TokenExchange,
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

        }  else if (configClient['credential-manager']) {

            return {
                credential_manager: {
                    credential_manager_id: configClient['credential-manager'],
                },
            };

        } else if (configClient['secret']) {

            return {
                secret: {
                    secret: configClient['secret'],
                },
            };

        } else if (configClient['no-authentication'] || configClient.capabilities['assisted-token']) {

            return {
                no_authentication: NoAuth.NoAuth,
            };

        } else {

            console.log(JSON.stringify(configClient, null, 2));
            throw new Error(`The client authentication method is not currently supported for ${configClient.id}`);
        }
    }

    private getSecondaryClientAuthentication(configClient: ConfigurationClient): ClientAuthenticationVerifierInput | null {

        const secondary = configClient['secondary-authentication-method']
        if (secondary) {

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
    
            } else if (secondary['secret']) {
    
                return {
                    secret: {
                        secret: secondary['secret'],
                    },
                };
    
            } else {

                throw new Error(`The secondary client authentication method is not currently supported for ${configClient.id}`);
            }
        }

        return null;
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

            throw new Error(`Assertion signing with a symmetric key is not supported for client ${configClient.id}`);
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
                allowed_content_encryption_alg: this.getContentEncryptionAlgorithm(idTokenEncryption['content-encryption-algorithm']),
                allowed_key_management_alg: this.getAsymmetricKeyManagementAlgorithm(idTokenEncryption['key-management-algorithm']),
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
                allow_deselection: consent['allow-deselection'] || null,
                only_consentors: consent['only-consentors'] || null,
                consentors: consent.consentors?.consentor || [],
            }
        }

        return userAuthentication;
    }

    private getContentEncryptionAlgorithm(configValue: ConfigClientContentEncryptionAlgorithm): ContentEncryptionAlgorithm {

        if (configValue === ConfigClientContentEncryptionAlgorithm.A128CBC_HS256) {
            
            return ContentEncryptionAlgorithm.A128CbcHs256;

        } else if (configValue === ConfigClientContentEncryptionAlgorithm.A128GCM) {

            return ContentEncryptionAlgorithm.A128Gcm;

        } else if (configValue === ConfigClientContentEncryptionAlgorithm.A192CBC_HS384) {

            return ContentEncryptionAlgorithm.A192CbcHs384;

        } else if (configValue === ConfigClientContentEncryptionAlgorithm.A192GCM) {

            return ContentEncryptionAlgorithm.A192Gcm;

        } else if (configValue === ConfigClientContentEncryptionAlgorithm.A256CBC_HS512) {

            return ContentEncryptionAlgorithm.A256CbcHs512;

        } else if (configValue === ConfigClientContentEncryptionAlgorithm.A256GCM) {

            return ContentEncryptionAlgorithm.A256Gcm;

        } else {

            throw new Error(`Unexpected content encryption algorithm: ${configValue}`);
        }
    }

    private getAsymmetricKeyManagementAlgorithm(configValue: ConfigClientAsymmetricKeyManagementAlgorithm): AsymmetricKeyManagementAlgorithm {

        if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.ECDH_ES) {

            return AsymmetricKeyManagementAlgorithm.EcdhEs;

        } else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.ECDH_ES_A128KW) {

            return AsymmetricKeyManagementAlgorithm.EcdhEsA128Kw;

        } else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.ECDH_ES_A192KW) {

            return AsymmetricKeyManagementAlgorithm.EcdhEsA192Kw;

        } else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.ECDH_ES_A256KW) {

            return AsymmetricKeyManagementAlgorithm.EcdhEsA256Kw;

        } else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.RSA1_5) {

            return AsymmetricKeyManagementAlgorithm.Rsa1_5;

        } else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.RSA_OAEP) {

            return AsymmetricKeyManagementAlgorithm.RsaOaep;

        }  else if (configValue == ConfigClientAsymmetricKeyManagementAlgorithm.RSA_OAEP_256) {

            return AsymmetricKeyManagementAlgorithm.RsaOaep_256;

        } else {

            throw new Error(`Unexpected assymetric key management algorithm: ${configValue}`);
        }
    }
}
