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

import { ObjectValues, SortOrderType } from './utils.js';
import { Capabilities } from './clients.js';

export enum RegistrationAuthenticationMethod {
  CLIENTS_MUST_AUTHENTICATE = 'clients-must-authenticate',
  USERS_MUST_AUTHENTICATE = 'users-must-authenticate',
}

export interface DatabaseClient {
  access_token_ttl: number | null;
  allow_per_request_redirect_uris: boolean | null;
  allowed_origins: string[] | null;
  application_url: string | null;
  audiences: string[];
  capabilities: DatabaseClientCapabilities;
  claim_mapper_id: string | null;
  client_authentication: ClientAuthentication;
  client_id: string;
  description: string | null;
  id_token: IdToken | null;
  logo_uri: string | null;
  name: string | null;
  policy_uri: string | null;
  properties: Record<string, string>;
  redirect_uri_validation_policy_id: string | null;
  redirect_uris: string[] | null;
  refresh_token: RefreshToken | null;
  request_object: RequestObject | null;
  require_secured_authorization_response: boolean;
  scopes: string[];
  sector_identifier: string | null;
  status: DatabaseClientStatus;
  subject_type: DatabaseClientSubjectType;
  tags: string[] | null;
  tos_uri: string | null;
  user_authentication: DatabaseClientUserAuthentication | null;
  userinfo_signed_issuer_id: string | null;
  validate_port_on_loopback_interfaces: boolean | null;
}

export type DatabaseClientStatus = 'ACTIVE' | 'INACTIVE' | 'REVOKED';

export type DatabaseClientSubjectType = 'pairwise' | 'public';

export interface RequestObject {
  allow_unsigned_for_by_value: boolean;
  by_reference: ByRefRequestObject | null;
  request_jwt_issuer: string | null;
  request_jwt_signature_verification_key: string | null;
}

export interface ByRefRequestObject {
  allow_unsigned_for: boolean;
  allowed_request_urls: string[];
  http_client_id: string | null;
}

export interface IdToken {
  id_token_ttl: number | null;
  id_token_encryption: JweEncryption | null;
}

export interface JweEncryption {
  allowed_content_encryption_alg: ContentEncryptionAlgorithmType;
  allowed_key_management_alg: AsymmetricKeyManagementAlgorithmType;
  encryption_key_id: string;
}

export const ContentEncryptionAlgorithm = {
  A128CBC_HS256: 'A128CBC_HS256',
  A128GCM: 'A128GCM',
  A192CBC_HS384: 'A192CBC_HS384',
  A192GCM: 'A192GCM',
  A256CBC_HS512: 'A256CBC_HS512',
  A256GCM: 'A256GCM',
} as const;

export type ContentEncryptionAlgorithmType = ObjectValues<typeof ContentEncryptionAlgorithm>;

export const AsymmetricKeyManagementAlgorithm = {
  ECDH_ES: 'ECDH_ES',
  ECDH_ES_A128KW: 'ECDH_ES_A128KW',
  ECDH_ES_A192KW: 'ECDH_ES_A192KW',
  ECDH_ES_A256KW: 'ECDH_ES_A256KW',
  RSA1_5: 'RSA1_5',
  RSA_OAEP: 'RSA_OAEP',
  RSA_OAEP_256: 'RSA_OAEP_256',
} as const;

export type AsymmetricKeyManagementAlgorithmType = ObjectValues<typeof AsymmetricKeyManagementAlgorithm>;

export interface DatabaseClientUserAuthentication {
  allowed_authenticators: string[];
  allowed_post_logout_redirect_uris: string[];
  authenticator_filters: string[];
  backchannel_logout_uri: string | null;
  consent: UserConsent | null;
  context_info: string;
  force_authentication: boolean | null;
  freshness: number | null;
  frontchannel_logout_uri: string | null;
  http_client_id: string | null;
  locale: string | null;
  required_claims: string[];
  template_area: string | null;
}

export interface ClientAuthentication {
  primary: ClientAuthenticationVerifierInput;
  secondary: ClientAuthenticationVerifierInput | null;
  secondary_verifier_expiration: number | null;
}

export interface ClientAuthenticationVerifierInput {
  asymmetric?: AsymmetricKeyInput;
  symmetric?: SymmetricKeyInput;
  credential_manager?: CredentialManagerInput;
  secret?: SecretInput;
  no_authentication?: NoAuth;
  mutual_tls?: MutualTlsInput;
  mutual_tls_by_proxy?: MutualTlsInput;
}

export interface MutualTlsInput {
  pinned_certificate?: PinnedCertificateInput;
  trusted_cas?: string[];
  dn?: DnMutualTlsInput;
  email?: EmailMutualTlsInput;
  uri?: UriMutualTlsInput;
  ip?: IpMutualTlsInput;
  dns?: DnsMutualTlsInput;
}

export interface DnMutualTlsInput {
  client_dn: string;
  trusted_cas: string[];
  rdns_to_match: string[];
}

export interface EmailMutualTlsInput {
  client_email: string;
  trusted_cas: string[];
}

export interface UriMutualTlsInput {
  client_uri: string;
  trusted_cas: string[];
}

export interface IpMutualTlsInput {
  client_ip: string;
  trusted_cas: string[];
}

export interface DnsMutualTlsInput {
  client_dns: string;
  trusted_cas: string[];
}

export interface PinnedCertificateInput {
  client_certificate_id: string;
}

export interface AsymmetricKeyInput {
  asymmetric_key_id: string;
}

export interface SymmetricKeyInput {
  symmetric_key: string;
}

export interface CredentialManagerInput {
  credential_manager_id: string;
}

export interface SecretInput {
  secret: string;
}

export interface AsymmetricKey {
  asymmetric_key_id: string;
}

export interface SymmetricKey {
  symmetric_key: string;
}

export interface MutualTlsVerifier {
  mutual_tls: MutualTls;
}

export interface MutualTlsByProxyVerifier {
  mutual_tls_by_proxy: MutualTls;
}

export interface CredentialManager {
  credential_manager_id: string;
}

export interface Secret {
  secret: string;
}

export interface NoAuthentication {
  no_authentication: NoAuth;
}

export enum NoAuth {
  no_auth = 'no_auth',
}

export interface Meta {
  created: number;
  lastModified: number;
}

export interface UserConsent {
  allow_deselection: boolean;
  consentors: string[];
  only_consentors: boolean;
}

export interface DatabaseClientCapabilities {
  assertion: AssertionCapability | null;
  assisted_token: AssistedTokenCapability | null;
  backchannel: BackchannelAuthenticationCapability | null;
  client_credentials: ClientCredentialsCapability | null;
  code: CodeCapability | null;
  haapi: HaapiCapability | null;
  implicit: ImplicitCapability | null;
  introspection: IntrospectionCapability | null;
  resource_owner_password: ResourceOwnerPasswordCredentialsCapability | null;
  token_exchange: TokenExchangeCapability | null;
}

export interface HaapiCapability {
  client_attestation: DatabaseClientAttestation;
  type: DatabaseClientHaapi;
  use_legacy_dpop: boolean;
}

export enum Web {
  WEB = 'WEB',
}

export enum Android {
  ANDROID = 'ANDROID',
}

export enum Ios {
  IOS = 'IOS',
}

export enum Disable {
  DISABLE = 'DISABLE',
}

export type DatabaseClientAttestationType = Web | Android | Ios | Disable;

export interface DatabaseClientAttestation {
  type: DatabaseClientAttestationType;
  policy_id?: string | null;

  // Android
  package_names?: string[];
  signature_fingerprints?: string[];

  // iOS
  app_id?: string;
}

export interface NoAttestation {
  type: Disable;
}

export enum DatabaseClientHaapi {
  HAAPI = 'HAAPI',
}

export interface TokenExchangeCapability {
  type: TokenExchange;
}

export enum TokenExchange {
  TOKEN_EXCHANGE = 'TOKEN_EXCHANGE',
}

export interface CodeCapability {
  proof_key: ProofKey | null;
  require_pushed_authorization_request: boolean | null;
  type: Code;
}

export enum Code {
  CODE = 'CODE',
}

export interface ProofKey {
  disallow_challenge_method_plain: boolean;
  disallow_challenge_method_s256: boolean;
  require_proof_key: boolean;
}

export interface ImplicitCapability {
  type: Implicit;
}

export enum Implicit {
  IMPLICIT = 'IMPLICIT',
}

export interface ResourceOwnerPasswordCredentialsCapability {
  credential_manager_id: string | null;
  type: ResourceOwnerPasswordCredentials;
}

export enum ResourceOwnerPasswordCredentials {
  ROPC = 'ROPC',
}

export interface AssertionCapability {
  jwt: JwtAssertion;
  type: Assertion;
}

export enum Assertion {
  ASSERTION = 'ASSERTION',
}

export interface ClientCredentialsCapability {
  type: ClientCredentials;
}

export enum ClientCredentials {
  CLIENT_CREDENTIALS = 'CLIENT_CREDENTIALS',
}

export interface JwtAssertion {
  allow_reuse: boolean;
  issuer: string | null;
  signing: JwtSigning;
}

export interface JwksUri {
  http_client_id: string | null;
  uri: string;
}

export interface JwtSigning {
  asymmetric_key_id?: string;
  symmetric_key?: string;
  jwks?: JwksUri;
}

export interface AssistedTokenCapability {
  type: AssistedToken;
}

export enum AssistedToken {
  ASSISTED_TOKEN = 'ASSISTED_TOKEN',
}

export interface BackchannelAuthenticationCapability {
  allowed_backchannel_authenticators: string[];
  type: BackchannelAuthentication;
}

export enum BackchannelAuthentication {
  BACKCHANNEL_AUTHENTICATION = 'BACKCHANNEL_AUTHENTICATION',
}

export interface IntrospectionCapability {
  type: Introspection;
}

export enum Introspection {
  INTROSPECTION = 'INTROSPECTION',
}

export interface RefreshToken {
  refresh_token_max_rolling_lifetime: number | null;
  refresh_token_ttl: number;
  reuse_refresh_tokens: boolean | null;
}

export type MutualTls =
  | DnMutualTls
  | DnsMutualTls
  | EmailMutualTls
  | IpMutualTls
  | PinnedCertificate
  | TrustedCaOnly
  | UriMutualTls;

export interface PinnedCertificate {
  client_certificate_id: string;
}

export interface NameAndCa {
  trusted_cas: string[];
}

export type TrustedCaOnly = NameAndCa;

export interface DnMutualTls extends NameAndCa {
  client_dn: string;
  rdns_to_match: string[];
}

export interface EmailMutualTls extends NameAndCa {
  client_email: string;
}

export interface UriMutualTls extends NameAndCa {
  client_uri: string;
}

export interface IpMutualTls extends NameAndCa {
  client_ip: string;
}

export interface DnsMutualTls extends NameAndCa {
  client_dns: string;
}

export interface CreateDatabaseClientInput {
  fields: DatabaseClientCreateFields;
}

// Todo: Derive this from the DatabaseClient type if possible
export interface DatabaseClientCreateFields {
  access_token_ttl: number;
  allow_per_request_redirect_uris: boolean | null;
  allowed_origins?: string[];
  application_url: string;
  audiences: string[];
  capabilities: CapabilitiesInput;
  claim_mapper_id: string;
  client_authentication: ClientAuthenticationInput;
  client_id: string;
  description: string;
  id_token: IdTokenInput;
  logo_uri: string;
  name: string;
  policy_uri: string;
  properties: Record<string, string>;
  redirect_uri_validation_policy_id: string;
  redirect_uris: string[];
  refresh_token: RefreshTokenInput;
  request_object: RequestObjectInput;
  require_secured_authorization_response: boolean;
  scopes: string[];
  sector_identifier: string;
  status: DatabaseClientStatus;
  subject_type: DatabaseClientSubjectType;
  tags?: string[];
  tos_uri: string;
  user_authentication: UserAuthenticationInput;
  userinfo_signed_issuer_id: string;
  validate_port_on_loopback_interfaces: boolean | null;
}

export interface ClientAuthenticationInput {
  primary: ClientAuthenticationVerifierInput;
  secondary?: ClientAuthenticationVerifierInput;
  secondary_verifier_expiration?: number;
}

export interface UserAuthenticationInput {
  allowed_authenticators?: string[];
  required_claims?: string[];
  context_info: string;
  template_area: string;
  force_authentication: boolean;
  freshness: number;
  locale: string;
  authenticator_filters?: string[];
  frontchannel_logout_uri: string;
  backchannel_logout_uri: string;
  http_client_id: string;
  allowed_post_logout_redirect_uris?: string[];
  consent: ConsentInput;
}

export interface RefreshTokenInput {
  refresh_token_ttl: number;
  refresh_token_max_rolling_lifetime?: number;
  reuse_refresh_tokens?: boolean;
}

export interface ConsentInput {
  only_consentors?: boolean;
  consentors?: string[];
  allow_deselection?: boolean;
}

export interface CapabilitiesInput {
  code: CodeCapabilityInput;
  implicit: ImplicitCapabilityInput;
  resource_owner_password: ResourceOwnerPasswordCredentialsCapabilityInput;
  assertion: AssertionCapabilityInput;
  assisted_token: AssistedTokenCapabilityInput;
  backchannel: BackchannelAuthenticationCapabilityInput;
  client_credentials: ClientCredentialsCapabilityInput;
  introspection: IntrospectionCapabilityInput;
  token_exchange: TokenExchangeCapabilityInput;
  haapi: HaapiCapabilityInput;
}

export interface CodeCapabilityInput {
  type: Code;
  proof_key?: ProofKeyInput;
  require_pushed_authorization_request?: boolean;
}

export interface ImplicitCapabilityInput {
  type: Implicit;
}

export interface ResourceOwnerPasswordCredentialsCapabilityInput {
  type: ResourceOwnerPasswordCredentials;
  credential_manager_id: string;
}

export interface ClientCredentialsCapabilityInput {
  type: ClientCredentials;
}

export interface IntrospectionCapabilityInput {
  type: Introspection;
}

export interface AssistedTokenCapabilityInput {
  type: AssistedToken;
}

export interface BackchannelAuthenticationCapabilityInput {
  type: BackchannelAuthentication;
  allowed_backchannel_authenticators?: string[];
}

export interface TokenExchangeCapabilityInput {
  type: TokenExchange;
}

export interface AssertionCapabilityInput {
  type: Assertion;
  jwt: JwtAssertionInput;
}

export interface HaapiCapabilityInput {
  type: DatabaseClientHaapi;
  use_legacy_dpop: boolean;
  client_attestation?: ClientAttestationInput;
}

export interface RequestObjectInput {
  request_jwt_signature_verification_key: string;
  request_jwt_issuer: string;
  by_reference: ByRefRequestObjectInput;
  allow_unsigned_for_by_value: boolean;
}

export interface IdTokenInput {
  id_token_ttl: number;
  id_token_encryption: JweEncryptionInput;
}

export interface ProofKeyInput {
  require_proof_key: boolean;
  disallow_challenge_method_s256?: boolean;
  disallow_challenge_method_plain?: boolean;
}

export interface JwtAssertionInput {
  issuer: string;
  signing: JwtSigningInput;
  allow_reuse: boolean;
}

export interface ClientAttestationInput {
  web?: WebAttestationInput;
  android?: AndroidAttestationInput;
  ios?: IosAttestationInput;
  no_attestation?: NoAttestationInput;
}

export interface WebAttestationInput {
  type: Web;
  policy_id: string;
}

export interface AndroidAttestationInput {
  type: Android;
  policy_id: string;
  package_names: string[];
  signature_fingerprints: string[];
}

export interface IosAttestationInput {
  type: Ios;
  policy_id: string;
  app_id: string;
}

export interface NoAttestationInput {
  type: Disable;
}

export interface ByRefRequestObjectInput {
  http_client_id: string;
  allowed_request_urls: string[];
  allow_unsigned_for: boolean;
}

export interface JweEncryptionInput {
  encryption_key_id: string;
  allowed_key_management_alg: AsymmetricKeyManagementAlgorithmType;
  allowed_content_encryption_alg: ContentEncryptionAlgorithmType;
}

export interface JwtSigningInput {
  asymmetric_key?: AsymmetricKeyInput;
  symmetric_key?: SymmetricKeyInput;
  jwks?: JwksUriInput;
}

export interface JwksUriInput {
  uri: string;
  http_client_id: string;
}

export type DatabaseClientsSortBy = 'name' | 'created' | 'lastModified';

export interface Sorting {
  sortBy: DatabaseClientsSortBy;
  sortOrder: SortOrderType;
}

export interface GetDatabaseClientsInput {
  activeClientsOnly?: boolean;
  clientName?: string;
  tags?: string[];
  first?: number;
  after?: string;
  sorting?: Sorting;
}

export interface GetDatabaseClientsResponse {
  databaseClients: {
    totalCount: number;
    edges: { node: DatabaseClientLean }[];
    pageInfo: { endCursor: string | null; hasNextPage: boolean };
  };
}

export interface GetDatabaseClientsResponseMapped {
  databaseClients: {
    totalCount: number;
    edges: { node: DatabaseClientLeanMapped }[];
    pageInfo: { endCursor: string | null; hasNextPage: boolean };
  };
}

export interface GetDatabaseClientByIdResponse {
  databaseClientById: DatabaseClient;
}

export type DatabaseClientUpdateFields = Partial<DatabaseClientCreateFields>;

export interface DatabaseClientLean {
  client_id: string;
  logo_uri: string;
  status: DatabaseClientStatus;
  meta: Meta;
  name: string;
  capabilities: DatabaseClientCapabilities;
}

export type DatabaseClientLeanMapped = Omit<DatabaseClientLean, 'capabilities'> & {
  capabilities: Capabilities;
};
