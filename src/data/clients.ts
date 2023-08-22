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

import { EmptyObject } from './utility-types.js';
import {
  AsymmetricKeyManagementAlgorithmType,
  ContentEncryptionAlgorithmType,
  RegistrationAuthenticationMethod,
} from './database-clients.js';
import { ObjectValues } from './utils.js';

export interface Client {
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

export interface JwksUri {
  uri: string;
  'http-client'?: string;
}

export interface MutualTls {
  'client-certificate'?: string;
  'client-dns-name'?: string;
  'client-email'?: string;
  'client-ip'?: string;
  'client-uri'?: string;
  'trusted-ca'?: string;
}

export interface IdTokenEncryption {
  'content-encryption-algorithm': ContentEncryptionAlgorithmType;
  'encryption-key': string;
  'key-management-algorithm': AsymmetricKeyManagementAlgorithmType;
}

export interface DynamicClientRegistrationTemplate {
  'credential-manager'?: string;
  'authenticate-user-by'?: string[];
  secret?: [null];
  'authenticate-client-by'?: string[];
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
  'resource-owner-password-credentials'?: EmptyObject;
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

export interface ClientLean {
  'client-name'?: string;
  capabilities: Capabilities;
  enabled: boolean;
  id: string;
}

export interface NewClientWizardData {
  ID_AND_TYPE: {
    id: string;
  };
  APP_DETAILS?: {
    capabilities: {
      code?: true;
      'device-authorization'?: true;
    };
    'user-authentication'?: {
      'backchannel-logout-uri'?: string;
      'frontchannel-logout-uri'?: string;
    };
    'redirect-uris'?: string[];
    'allowed-origins'?: string[];
  };
  CLIENT_AUTHENTICATION: {
    'asymmetric-key'?: string;
    'client-authentication-method': ClientAuthenticationMethodType;
    'credential-manager'?: string;
    'no-authentication'?: true;
    'symmetric-key'?: string;
    secret?: string;
    'jwks-uri'?: {
      uri: string;
    };
  };
  USER_AUTHENTICATION?: {
    'user-authentication': {
      'allowed-authenticators'?: string[];
    };
  };
  SELECT_SCOPES: {
    'openid-connect'?: boolean;
    'openid-connect-user-info'?: boolean;
    scope?: string[];
  };
  DCR_REGISTRATION?: {
    'dynamic-client-registration-template': {
      'client-authentication-method': ClientAuthenticationMethodType;
      'registration-authentication-method': RegistrationAuthenticationMethod;
      'authenticate-user-by'?: string[];
      'credential-manager'?: string;
    };
  };
}

export const ClientAuthenticationMethod = {
  ASYMMETRIC_KEY: 'asymmetric-key',
  CREDENTIAL_MANAGER: 'credential-manager',
  JWKS_URI: 'jwks-uri',
  MUTUAL_TLS: 'mutual-tls',
  MUTUAL_TLS_BY_PROXY: 'mutual-tls-by-proxy',
  NO_AUTHENTICATION: 'no-authentication',
  SECRET: 'secret',
  SYMMETRIC_KEY: 'symmetric-key',
} as const;

export type ClientAuthenticationMethodType = ObjectValues<typeof ClientAuthenticationMethod>;
