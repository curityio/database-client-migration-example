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

export enum ContentEncryptionAlgorithm {
  A128CBC_HS256 = 'A128CBC-HS256',
  A128GCM = 'A128GCM',
  A192CBC_HS384 = 'A192CBC-HS384',
  A192GCM = 'A192GCM',
  A256CBC_HS512 = 'A256CBC-HS512',
  A256GCM = 'A256GCM',
}

export enum AsymmetricKeyManagementAlgorithm {
  ECDH_ES = 'ECDH-ES',
  ECDH_ES_A128KW = 'ECDH-ES+A128KW',
  ECDH_ES_A192KW = 'ECDH-ES+A192KW',
  ECDH_ES_A256KW = 'ECDH-ES+A256KW',
  RSA1_5 = 'RSA1_5',
  RSA_OAEP = 'RSA-OAEP',
  RSA_OAEP_256 = 'RSA-OAEP-256',
}

export interface ConfigurationClient {
  'access-token-ttl': number;
  'allowed-origins'?: string[];
  'application-url'?: string;
  'asymmetric-key'?: string;
  'claims-mapper'?: string;
  'client-authentication-method'?: string;
  'client-name'?: string;
  'credential-manager'?: string;
  'dynamic-client-registration-template'?: DynamicClientRegistrationTemplate;
  'id-token-encryption'?: IdTokenEncryption;
  'id-token-ttl'?: number;
  'jwks-uri'?: JwksUri;
  'mutual-tls'?: MutualTls;
  'mutual-tls-by-proxy'?: MutualTls;
  'no-authentication'?: boolean;
  'privacy-policy-url'?: string;
  'proof-key'?: ProofKey;
  'redirect-uri-validation-policy'?: string;
  'redirect-uris'?: string[];
  'refresh-token-max-rolling-lifetime'?: number | 'disabled';
  'refresh-token-ttl'?: number | 'disabled';
  'request-object'?: RequestObject;
  'require-secured-authorization-response'?: [null];
  'reuse-refresh-tokens'?: boolean;
  'secondary-authentication-method'?: SecondaryAuthenticationMethod;
  'signed-userinfo'?: SignedUserinfo;
  'symmetric-key'?: string;
  'terms-of-service-url'?: string;
  'use-pairwise-subject-identifiers'?: UsePairwiseSubjectIdentifiers;
  'user-authentication'?: UserAuthentication;
  'user-consent'?: UserConsent;
  'validate-port-on-loopback-interfaces': boolean;
  attestation?: Attestation;
  audience?: string[];
  capabilities: Capabilities;
  description?: string;
  enabled: boolean;
  id: string;
  logo?: string;
  properties?: Properties;
  scope: string[];
  secret?: string;
}

export interface SecondaryAuthenticationMethod {
  'asymmetric-key'?: string;
  'credential-manager'?: string;
  'expires-on'?: string;
  'jwks-uri'?: JwksUri;
  'mutual-tls-by-proxy'?: MutualTls;
  'mutual-tls'?: MutualTls;
  'no-authentication'?: boolean;
  'symmetric-key'?: string;
  secret?: string;
}

export interface DynamicClientRegistrationTemplate {
  'credential-manager'?: string;
  'authenticate-user-by'?: string[];
  secret?: [null];
  'authenticate-client-by'?: string[];
}

export interface JwksUri {
  uri: string;
  'http-client'?: string;
}

export interface MutualTls {
  'client-certificate'?: string;
  'client-dn'?: string;
  'client-dns-name'?: string;
  'client-email'?: string;
  'client-ip'?: string;
  'client-uri'?: string;
  'trusted-ca'?: string;
}

export interface IdTokenEncryption {
  'content-encryption-algorithm': ContentEncryptionAlgorithm;
  'encryption-key': string;
  'key-management-algorithm': AsymmetricKeyManagementAlgorithm;
}

export interface SignedUserinfo {
  'userinfo-token-issuer': string;
}

export interface UserConsent {
  'allow-deselection': boolean;
  'only-consentors': boolean;
  consentors?: Consentors;
}

export interface Consentors {
  consentor: string[];
}

export interface ByReference {
  'http-client'?: string;
  'allowed-request-url'?: string[];
  'allow-unsigned': boolean;
}

export interface RequestObject {
  issuer?: string;
  'by-reference'?: ByReference;
  'signature-verification-key'?: string;
  'allow-unsigned-for-by-value': boolean;
}

export interface UsePairwiseSubjectIdentifiers {
  'sector-identifier'?: string;
}

export interface BackchannelLogoutURI {
  tags: string[];
}

export type AttestationType = 'android' | 'web' | 'ios';

export interface Attestation {
  'attestation-type': AttestationType;
  'disable-attestation-validation': boolean;
  web?: Web;
  android?: Android;
  ios?: Ios;
}

export interface Web {
  'web-policy': string;
}

export interface Android {
  'package-name': string[];
  'signature-digest': string[];
  'android-policy': string;
}

export interface Ios {
  'app-id': string;
  'ios-policy': string;
}

export interface AssertionCapability {
  jwt: {
    'allow-reuse': boolean;
    trust: {
      'asymmetric-signing-key'?: string;
      issuer?: string;
      'jwks-uri'?: {
        'http-client'?: string;
        uri: string;
      };
    };
  };
}

export interface Capabilities {
  'assisted-token'?: [null];
  'backchannel-authentication'?: BackChannelAuthenticationCapability;
  'client-credentials'?: [null];
  'device-authorization'?: [null];
  'resource-owner-password-credentials'?: ResourceOwnerPasswordCapability;
  'token-exchange'?: [null];
  assertion?: AssertionCapability;
  code?: CodeCapability;
  haapi?: Haapi;
  implicit?: [null];
  introspection?: [null];
}

export interface CodeCapability {
  'require-pushed-authorization-requests'?: {
    'allow-per-request-redirect-uris'?: boolean;
  };
}

export interface ResourceOwnerPasswordCapability {
  'credential-manager'?: string;
}

export interface BackChannelAuthenticationCapability {
  'allowed-authenticators': string[];
}

export interface Haapi {
  'allow-without-attestation': boolean;
  'use-legacy-dpop': boolean;
}

export interface ProofKey {
  'disallowed-proof-key-challenge-methods': string[];
  'require-proof-key': boolean;
}

export interface Properties {
  property: Property[];
}

export interface Property {
  key: string;
  value: string;
}

export interface UserAuthentication {
  'allowed-authenticators'?: string[];
  'allowed-post-logout-redirect-uris'?: string[];
  'authenticator-filters'?: string[];
  'backchannel-logout-uri'?: string;
  'context-info'?: string;
  'force-authn'?: boolean;
  'frontchannel-logout-uri'?: string;
  'http-client'?: string;
  'required-claims'?: string[];
  'template-area'?: string;
  freshness?: number;
  locale?: string;
}
