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

import {
  AsymmetricKeyManagementAlgorithm,
  ContentEncryptionAlgorithm,
} from './databaseClient.js';

export interface ConfigurationClient {
  'access-token-ttl': number;
  'allowed-origins'?: string[];
  'application-url'?: string;
  'asymmetric-key'?: string;
  'claims-mapper'?: string;
  'client-authentication-method'?: string;
  'client-name'?: string;
  'credential-manager'?: string;
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
