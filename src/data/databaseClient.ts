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

export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
export type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
export type MakeOptional<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]?: Maybe<T[SubKey]> };
export type MakeMaybe<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]: Maybe<T[SubKey]> };
export type MakeEmpty<T extends { [key: string]: unknown }, K extends keyof T> = { [_ in K]?: never };
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: { input: string; output: string; }
  String: { input: string; output: string; }
  Boolean: { input: boolean; output: boolean; }
  Int: { input: number; output: number; }
  Float: { input: number; output: number; }
  /** A 64-bit signed integer */
  Long: { input: any; output: any; }
  /** An object scalar */
  Object: { input: any; output: any; }
};

/** Android client attestation */
export enum Android {
  /** Android client attestation */
  Android = 'ANDROID'
}

/** Android client attestation configuration */
export type AndroidAttestation = {
  __typename?: 'AndroidAttestation';
  /** Android package names that should be allowed to perform client attestation */
  package_names: Array<Scalars['String']['output']>;
  /** Attestation policy ID */
  policy_id?: Maybe<Scalars['String']['output']>;
  /** Android package signature fingerprints that should be allowed to perform client attestation */
  signature_fingerprints: Array<Scalars['String']['output']>;
  /** Type of client attestation */
  type: Android;
};

/** Android client attestation configuration */
export type AndroidAttestationInput = {
  /** Android package names that should be allowed to perform client attestation */
  package_names: Array<Scalars['String']['input']>;
  /** Attestation policy ID */
  policy_id?: InputMaybe<Scalars['String']['input']>;
  /** Android package signature fingerprints that should be allowed to perform client attestation */
  signature_fingerprints: Array<Scalars['String']['input']>;
  /** Type of client attestation */
  type: Android;
};

/** Assertion capability type */
export enum Assertion {
  /** Assertion capability type */
  Assertion = 'ASSERTION'
}

/**
 * Allows the client to use JWT assertions as grant.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type AssertionCapability = {
  __typename?: 'AssertionCapability';
  /** Configures the assertion grant for JWT assertions. */
  jwt: JwtAssertion;
  /** Type of the assertion capability */
  type: Assertion;
};

/**
 * Allows the client to use JWT assertions as grant.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type AssertionCapabilityInput = {
  /** Configures the assertion grant for JWT assertions. */
  jwt: JwtAssertionInput;
  /** Type of the assertion capability */
  type: Assertion;
};

/** Assisted token capability type */
export enum AssistedToken {
  /** Assisted token capability type */
  AssistedToken = 'ASSISTED_TOKEN'
}

/**
 * The assisted-token capability allows the client to use a helper endpoint to use
 * simplified OAuth flows.
 *
 * When enabled, the client must configure at least one `allowed_origins`
 * to allow the Assisted Token flow to be enabled.
 */
export type AssistedTokenCapability = {
  __typename?: 'AssistedTokenCapability';
  /** Type of the assisted token capability */
  type: AssistedToken;
};

/**
 * The assisted-token capability allows the client to use a helper endpoint to use
 * simplified OAuth flows.
 *
 * When enabled, the client must configure at least one `allowed_origins`
 * to allow the Assisted Token flow to be enabled.
 */
export type AssistedTokenCapabilityInput = {
  /** Type of the assisted token capability */
  type: AssistedToken;
};

/** Asymmetric key configuration */
export type AsymmetricKey = {
  __typename?: 'AsymmetricKey';
  /**
   * ID of a public key that corresponds to the private key the client will use to sign a token
   * with to authenticate itself.
   *
   * Asymmetrically signed JWT Client authentication must be enabled in the profile.
   */
  asymmetric_key_id: Scalars['String']['output'];
};

/** Asymmetric key configuration */
export type AsymmetricKeyInput = {
  /**
   * ID of a public key that corresponds to the private key the client will use to sign a token
   * with to authenticate itself.
   *
   * Asymmetrically signed JWT Client authentication must be enabled in the profile.
   */
  asymmetric_key_id: Scalars['String']['input'];
};

/** Algorithms supported to encrypt the content encryption key, present as 'alg' in JWE header. */
export enum AsymmetricKeyManagementAlgorithm {
  /** ECDH ES algorithm */
  EcdhEs = 'ECDH_ES',
  /** ECDH ES A128KW algorithm */
  EcdhEsA128Kw = 'ECDH_ES_A128KW',
  /** ECDH ES A192KW algorithm */
  EcdhEsA192Kw = 'ECDH_ES_A192KW',
  /** ECDH ES A256KW algorithm */
  EcdhEsA256Kw = 'ECDH_ES_A256KW',
  /** RSA 1.5 algorithm */
  Rsa1_5 = 'RSA1_5',
  /** RSA OAEP algorithm */
  RsaOaep = 'RSA_OAEP',
  /** RSA OAEP 256 algorithm */
  RsaOaep_256 = 'RSA_OAEP_256'
}

/** Backchannel authentication capability type */
export enum BackchannelAuthentication {
  /** Backchannel authentication capability type */
  BackchannelAuthentication = 'BACKCHANNEL_AUTHENTICATION'
}

/**
 * Allows the client to perform backchannel authentication.
 *
 * `user_authentication` controls whether user authentication is enabled.
 *
 * The client MUST have the `openid` scope when using this capability, and
 * must NOT set `client_authentication` to `NoAuthentication`.
 */
export type BackchannelAuthenticationCapability = {
  __typename?: 'BackchannelAuthenticationCapability';
  /**
   * A list of backchannel enabled authenticators that the client is allowed to use.
   * Should be a subset of backchannel authenticators from the linked authentication profile.
   * If empty, all backchannel-authenticators from the linked authentication profile
   * will be available for this client to use.
   */
  allowed_backchannel_authenticators: Array<Scalars['String']['output']>;
  /** Type of the backchannel authentication capability */
  type: BackchannelAuthentication;
};

/**
 * Allows the client to perform backchannel authentication.
 *
 * `user_authentication` controls whether user authentication is enabled.
 *
 * The client MUST have the `openid` scope when using this capability, and
 * must NOT set `client_authentication` to `NoAuthentication`.
 */
export type BackchannelAuthenticationCapabilityInput = {
  /**
   * A list of backchannel enabled authenticators that the client is allowed to use.
   * Should be a subset of backchannel authenticators from the linked authentication profile.
   * If nothing is set, all backchannel-authenticators from the linked authentication profile
   * will be available for this client to use.
   */
  allowed_backchannel_authenticators?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Type of the backchannel authentication capability */
  type: BackchannelAuthentication;
};

/** Request Object by-ref configuration */
export type ByRefRequestObject = {
  __typename?: 'ByRefRequestObject';
  /** If set to true, then unsigned request objects sent by-reference will be accepted. */
  allow_unsigned_for?: Maybe<Scalars['Boolean']['output']>;
  /**
   * Locations that can be included in a request_uri parameter.
   * The value '*' allows for any.
   * A wildcard character '*' is also allowed at the end of the uri value.
   */
  allowed_request_urls: Array<Scalars['String']['output']>;
  /** The HTTP client that will be used when fetching the request object from a provided URI. */
  http_client_id?: Maybe<Scalars['String']['output']>;
};

/** Request Object by-ref configuration */
export type ByRefRequestObjectInput = {
  /** If set to true, then unsigned request objects sent by-reference will be accepted. */
  allow_unsigned_for?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * Locations that can be included in a request_uri parameter.
   * The value '*' allows for any.
   * A wildcard character '*' is also allowed at the end of the uri value.
   */
  allowed_request_urls: Array<Scalars['String']['input']>;
  /** The HTTP client that will be used when fetching the request object from a provided URI. */
  http_client_id?: InputMaybe<Scalars['String']['input']>;
};

/**
 * OAuth capabilities that this client is allowed to perform.
 *
 * At least one client capability (besides HAAPI) should be enabled.
 */
export type Capabilities = {
  __typename?: 'Capabilities';
  /** Assertion capability */
  assertion?: Maybe<AssertionCapability>;
  /** Assisted token capability */
  assisted_token?: Maybe<AssistedTokenCapability>;
  /** Backchannel authentication capability */
  backchannel?: Maybe<BackchannelAuthenticationCapability>;
  /** Client-credentials capability */
  client_credentials?: Maybe<ClientCredentialsCapability>;
  /** Code capability */
  code?: Maybe<CodeCapability>;
  /** HAAPI capability */
  haapi?: Maybe<HaapiCapability>;
  /** Implicit capability */
  implicit?: Maybe<ImplicitCapability>;
  /** Introspection capability */
  introspection?: Maybe<IntrospectionCapability>;
  /** Resource-owner password credentials capability */
  resource_owner_password?: Maybe<ResourceOwnerPasswordCredentialsCapability>;
  /** Token exchange capability */
  token_exchange?: Maybe<TokenExchangeCapability>;
};

/**
 * OAuth capabilities that this client is allowed to perform.
 *
 * At least one client capability (besides HAAPI) should be enabled.
 */
export type CapabilitiesInput = {
  /** Assertion capability */
  assertion?: InputMaybe<AssertionCapabilityInput>;
  /** Assisted token capability */
  assisted_token?: InputMaybe<AssistedTokenCapabilityInput>;
  /** Backchannel authentication capability */
  backchannel?: InputMaybe<BackchannelAuthenticationCapabilityInput>;
  /** Client-credentials capability */
  client_credentials?: InputMaybe<ClientCredentialsCapabilityInput>;
  /** Code capability */
  code?: InputMaybe<CodeCapabilityInput>;
  /** HAAPI capability */
  haapi?: InputMaybe<HaapiCapabilityInput>;
  /** Implicit capability */
  implicit?: InputMaybe<ImplicitCapabilityInput>;
  /** Introspection capability */
  introspection?: InputMaybe<IntrospectionCapabilityInput>;
  /** Resource-owner password credentials capability */
  resource_owner_password?: InputMaybe<ResourceOwnerPasswordCredentialsCapabilityInput>;
  /** Token exchange capability */
  token_exchange?: InputMaybe<TokenExchangeCapabilityInput>;
};

/** Client attestation configuration */
export type ClientAttestation = AndroidAttestation | IosAttestation | NoAttestation | WebAttestation;

/** This is an union type. Only one of the fields must be set. */
export type ClientAttestationInput = {
  /** Android client attestation */
  android?: InputMaybe<AndroidAttestationInput>;
  /** IOS client attestation */
  ios?: InputMaybe<IosAttestationInput>;
  /** Disable client attestation */
  no_attestation?: InputMaybe<NoAttestationInput>;
  /** Web client attestation */
  web?: InputMaybe<WebAttestationInput>;
};

/** Describes how the client is authenticated */
export type ClientAuthentication = {
  __typename?: 'ClientAuthentication';
  /** The primary way to authenticate this client. */
  primary: ClientAuthenticationVerifier;
  /**
   * Optional additional client authentication method, used if the primary one was unsuccessful.
   *
   * Allows for high-availability during credential rotation or authentication method upgrades.
   */
  secondary?: Maybe<ClientAuthenticationVerifier>;
  /**
   * The instant after which the secondary verifier should not be used.
   *
   * The unit of this value is epoch-seconds.
   */
  secondary_verifier_expiration?: Maybe<Scalars['Long']['output']>;
};

/** Describes how the client is authenticated */
export type ClientAuthenticationInput = {
  /** The primary way to authenticate this client. */
  primary: ClientAuthenticationVerifierInput;
  /**
   * Optional additional client authentication method, used if the primary one was unsuccessful.
   *
   * Allows for high-availability during credential rotation or authentication method upgrades.
   */
  secondary?: InputMaybe<ClientAuthenticationVerifierInput>;
  /**
   * The instant after which the secondary verifier should not be used.
   *
   * The unit of this value is epoch-seconds.
   */
  secondary_verifier_expiration?: InputMaybe<Scalars['Long']['input']>;
};

/** Client authentication verifier */
export type ClientAuthenticationVerifier = AsymmetricKey | CredentialManager | MutualTlsByProxyVerifier | MutualTlsVerifier | NoAuthentication | Secret | SymmetricKey;

/** This is an union type. Only one of the fields must be set. */
export type ClientAuthenticationVerifierInput = {
  /** Asymmetric key */
  asymmetric?: InputMaybe<AsymmetricKeyInput>;
  /** Credential manager */
  credential_manager?: InputMaybe<CredentialManagerInput>;
  /** Mutual TLS authentication */
  mutual_tls?: InputMaybe<MutualTlsInput>;
  /** Mutual TLS by proxy authentication */
  mutual_tls_by_proxy?: InputMaybe<MutualTlsInput>;
  /** Disable client authentication */
  no_authentication?: InputMaybe<NoAuth>;
  /** Client secret */
  secret?: InputMaybe<SecretInput>;
  /** Symmetric key */
  symmetric?: InputMaybe<SymmetricKeyInput>;
};

/** Client credentials flow capability type */
export enum ClientCredentials {
  /** Client credentials flow capability type */
  ClientCredentials = 'CLIENT_CREDENTIALS'
}

/**
 * Allows for the Client Credentials Grant.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type ClientCredentialsCapability = {
  __typename?: 'ClientCredentialsCapability';
  /** Type of the client-credentials capability */
  type: ClientCredentials;
};

/**
 * Allows for the Client Credentials Grant.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type ClientCredentialsCapabilityInput = {
  /** Type of the client-credentials capability */
  type: ClientCredentials;
};

/** Code flow capability type */
export enum Code {
  /** Code flow capability type */
  Code = 'CODE'
}

/** Code capability */
export type CodeCapability = {
  __typename?: 'CodeCapability';
  /**
   * Proof Key for Code Exchange (RFC 7636 - PKCE) is a measure for preventing authorization code interception.
   * This is an attack on client systems that allow a malicious application to
   * register itself as a handler for the custom scheme
   * utilized by the legitimate app in the Authorization Code Grant flow.
   */
  proof_key?: Maybe<ProofKey>;
  /**
   * When enabled, the client is required to use Pushed Authorization Requests
   * when starting a code flow.
   */
  require_pushed_authorization_request?: Maybe<Scalars['Boolean']['output']>;
  /** Type of the code capability */
  type: Code;
};

/** Code capability */
export type CodeCapabilityInput = {
  /**
   * Proof Key for Code Exchange (RFC 7636 - PKCE) is a measure for preventing authorization code interception.
   * This is an attack on client systems that allow a malicious application to
   * register itself as a handler for the custom scheme
   * utilized by the legitimate app in the Authorization Code Grant flow.
   */
  proof_key?: InputMaybe<ProofKeyInput>;
  /**
   * When enabled, the client is required to use Pushed Authorization Requests
   * when starting a code flow.
   */
  require_pushed_authorization_request?: InputMaybe<Scalars['Boolean']['input']>;
  /** Type of the code capability */
  type: Code;
};

/** User consent configuration */
export type ConsentInput = {
  /**
   * When enabled, the user is allowed to deselect optional scopes or claims when
   * asked for consent.
   */
  allow_deselection?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * The consentors usable with this client.
   *
   * If empty or not provided, then all profile consentors will be usable.
   */
  consentors?: InputMaybe<Array<Scalars['String']['input']>>;
  /** When enabled, the built-in consent screen will not be shown and only the consentors will run. */
  only_consentors?: InputMaybe<Scalars['Boolean']['input']>;
};

/** Supported content encryption algorithms, present as 'enc' in JWE header. */
export enum ContentEncryptionAlgorithm {
  /** A128CBC HS256 algorithm */
  A128CbcHs256 = 'A128CBC_HS256',
  /** A128CBC GCM algorithm */
  A128Gcm = 'A128GCM',
  /** A192CBC HS384 algorithm */
  A192CbcHs384 = 'A192CBC_HS384',
  /** A192CBC GCM algorithm */
  A192Gcm = 'A192GCM',
  /** A256CBC HS512 algorithm */
  A256CbcHs512 = 'A256CBC_HS512',
  /** A256CBC GCM algorithm */
  A256Gcm = 'A256GCM'
}

/** Input of the create operation. */
export type CreateDatabaseClientInput = {
  /** The fields to create the client from. */
  fields: DatabaseClientCreateFields;
};

/** Response containing a database client's attributes. */
export type CreateDatabaseClientPayload = {
  __typename?: 'CreateDatabaseClientPayload';
  /** The created client. */
  client: DatabaseClient;
};

/** Credential manager configuration. */
export type CredentialManager = {
  __typename?: 'CredentialManager';
  /**
   * The Credential Manager to use to transform the client secret.
   *
   * For configured clients, this credential manager is also used to retrieve the client secret from the
   * configured data source on the credential manager.
   */
  credential_manager_id: Scalars['String']['output'];
};

/** Credential manager configuration. */
export type CredentialManagerInput = {
  /**
   * The Credential Manager to use to transform the client secret.
   *
   * For configured clients, this credential manager is also used to retrieve the client secret from the
   * configured data source on the credential manager.
   */
  credential_manager_id: Scalars['String']['input'];
};

/** Database client configuration. */
export type DatabaseClient = {
  __typename?: 'DatabaseClient';
  /** The Time To Live for an access token. */
  access_token_ttl: Scalars['Long']['output'];
  /**
   * Allow clients to register with the allow per request redirect uri setting.
   * Can only be enabled for the code flow with pushed authorization requests and when this setting
   * is allowed on the profile.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  allow_per_request_redirect_uris?: Maybe<Scalars['Boolean']['output']>;
  /**
   * The optional list of URIs or URI-patterns that is allowed to embed the rendered pages inside
   * an iframe, be a trusted source or be used for CORS.
   */
  allowed_origins?: Maybe<Array<Scalars['String']['output']>>;
  /**
   * This URL is used if a request is made to the OAuth server without the parameters necessary
   * to initiate authentication.
   * In such a case, the user is redirected to this URL, so that a new, properly
   * formed, request can be made to bootstrap a new authentication transaction.
   */
  application_url?: Maybe<Scalars['String']['output']>;
  /**
   * The intended audiences for the token.
   * The first element is the default. If none are stipulated,
   * the ID of the client will be used as the audience.
   */
  audiences: Array<Scalars['String']['output']>;
  /** Client capabilities. A Client must have at least one capability. */
  capabilities: Capabilities;
  /**
   * The mapper to use when adding claims to tokens.
   * The mapper decides what claims end up in which token or response.
   * The claims themselves are defined in the scope.
   * If not set, the default-mapper is used.
   */
  claim_mapper_id?: Maybe<Scalars['String']['output']>;
  /**
   * Mechanism used by this client to authenticate.
   * One must be selected. For public clients, select a primary method
   * of `NoAuthentication`.
   */
  client_authentication: ClientAuthentication;
  /** OAuth client_id, unique only within a single profile. */
  client_id: Scalars['ID']['output'];
  /** A human readable description of the client. */
  description?: Maybe<Scalars['String']['output']>;
  /** Configuration for ID Tokens. */
  id_token?: Maybe<IdToken>;
  /**
   * A logo of the client, that can be shown in user interface templates.
   *
   * A "data:" URL with media type among: png, jpeg, gif, svg+xml.
   */
  logo_uri?: Maybe<Scalars['String']['output']>;
  /** Metadata related to this client. */
  meta?: Maybe<Meta>;
  /** A human readable name of the client. */
  name: Scalars['String']['output'];
  /**
   * The owner of the database client who has administrative rights on it.
   * By default, this is the user or client which created the database client.
   */
  owner: Scalars['String']['output'];
  /** An absolute URL that refers to the privacy policy for the client. */
  policy_uri?: Maybe<Scalars['String']['output']>;
  /** Field with the extra client properties not covered in the schema. */
  properties: Scalars['Object']['output'];
  /**
   * The redirect uri validation policy ID to use for this client.
   *
   * This value overrides the profile's setting for the default redirect uri validation policy.
   */
  redirect_uri_validation_policy_id?: Maybe<Scalars['String']['output']>;
  /**
   * The client redirect URIs.
   * Mandatory if the client has the [CodeCapability].
   */
  redirect_uris?: Maybe<Array<Scalars['String']['output']>>;
  /**
   * Configuration for Refresh Tokens.
   * If not set, refresh tokens are automatically issued when the client is configured with one of the following
   * capability: Code flow, ROPC, Backchannel authentication. Otherwise refresh tokens will not be issued.
   * To explicitly disable refresh tokens issuance, configure this field with a refresh_token_ttl set to 0 seconds.
   */
  refresh_token?: Maybe<RefreshToken>;
  /**
   * Enable request-object support where the client can send in a JWT
   * with the request parameters.
   * If set, a request object JWT MUST be provided by the client.
   */
  request_object?: Maybe<RequestObject>;
  /**
   * If `true`, then all authorization responses need to be protected according to the
   * 'JWT Secured Authorization Response Mode for OAuth 2.0' (JARM) specification.
   *
   * Secured authorization responses requires the default-token-issuer on the profile to have
   * jwt-issuer-settings enabled, and the client must have the code or implicit capabilities enabled.
   */
  require_secured_authorization_response: Scalars['Boolean']['output'];
  /** The scopes of this client. */
  scopes: Array<Scalars['String']['output']>;
  /**
   * The sector identifier that is used to derive the pairwise pseudonym from,
   * i.e. the pairwise pseudonym is defined for the pair of sector identifier and subject.
   *
   * Only used if `subject_type` is set to `pairwise`.
   */
  sector_identifier?: Maybe<Scalars['String']['output']>;
  /** Current status of this client. */
  status: DatabaseClientStatus;
  /**
   * Whether the client should issue pairwise pseudonym subject identifiers
   * or public identifiers.
   *
   * When set to `pairwise`, the client must have at least one redirect-uri configured,
   * or it must set a `sector_identifier` to use,
   * and MUST NOT have the `ResourceOwnerPasswordCredentialsCapability`.
   */
  subject_type: SubjectType;
  /** Optional list of tags categorizing this client, thus allowing to easily filter clients in chosen categories. */
  tags?: Maybe<Array<Scalars['String']['output']>>;
  /** An absolute URL that refers to the terms of service of the client. */
  tos_uri?: Maybe<Scalars['String']['output']>;
  /** Enable client to perform user authentication. */
  user_authentication?: Maybe<UserAuthentication>;
  /**
   * A token issuer with a purpose of userinfo.
   *
   * Enables support for returning userinfo as signed JWT.
   */
  userinfo_signed_issuer_id?: Maybe<Scalars['String']['output']>;
  /**
   * Whether the port should be validated when a client is configured to redirect to the loopback interface.
   * Defaults to false because RFC-8252 (sec. 3) says the port should not be
   * validated and this does not generally reduces the security of local redirects.
   * This option can not be set when the profile enables redirect-uri validation policies.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  validate_port_on_loopback_interfaces?: Maybe<Scalars['Boolean']['output']>;
};

/** Client connection. */
export type DatabaseClientConnection = {
  __typename?: 'DatabaseClientConnection';
  /** The list of edges containing the database client nodes. */
  edges?: Maybe<Array<Maybe<DatabaseClientEdge>>>;
  /** Pagination information for this connection. */
  pageInfo: PageInfo;
  /** Total number of database clients based on input parameters, recommended to include only in the request for initial page. */
  totalCount: Scalars['Long']['output'];
};

/** Database client creation attributes. */
export type DatabaseClientCreateFields = {
  /** The Time To Live for an access token. */
  access_token_ttl?: InputMaybe<Scalars['Long']['input']>;
  /**
   * Allow clients to register with the allow per request redirect uri setting.
   * Can only be enabled for the code flow with pushed authorization requests and when this setting
   * is allowed on the profile. Defaults to false.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  allow_per_request_redirect_uris?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * The optional list of URIs or URI-patterns that is allowed to embed the rendered pages inside
   * an iframe, be a trusted source or be used for CORS.
   */
  allowed_origins?: InputMaybe<Array<Scalars['String']['input']>>;
  /**
   * This URL is used if a request is made to the OAuth server without the parameters necessary
   * to initiate authentication.
   * In such a case, the user is redirected to this URL, so that a new, properly
   * formed, request can be made to bootstrap a new authentication transaction.
   */
  application_url?: InputMaybe<Scalars['String']['input']>;
  /**
   * The intended audiences for the token.
   * The first element is the default. If none are stipulated,
   * the ID of the client will be used as the audience.
   */
  audiences?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Client capabilities. A Client must have at least one capability. */
  capabilities: CapabilitiesInput;
  /**
   * The mapper to use when adding claims to tokens.
   * The mapper decides what claims end up in which token or response.
   * The claims themselves are defined in the scope.
   * If not set, the default-mapper is used.
   */
  claim_mapper_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * Mechanism used by this client to authenticate.
   * One must be selected. For public clients, select a primary method
   * of `NoAuthentication`.
   */
  client_authentication?: InputMaybe<ClientAuthenticationInput>;
  /**
   * OAuth client_id, unique only within a single profile.
   *
   * If not provided, a value is generated.
   */
  client_id?: InputMaybe<Scalars['ID']['input']>;
  /** A human readable description of the client. */
  description?: InputMaybe<Scalars['String']['input']>;
  /** Configuration for ID Tokens. */
  id_token?: InputMaybe<IdTokenInput>;
  /**
   * A logo of the client, that can shown in user interface templates.
   *
   * A "data:" URL with media type among: png, jpeg, gif, svg+xml.
   */
  logo_uri?: InputMaybe<Scalars['String']['input']>;
  /** A human readable name of the client. */
  name?: InputMaybe<Scalars['String']['input']>;
  /** An absolute URL that refers to the privacy policy for the client. */
  policy_uri?: InputMaybe<Scalars['String']['input']>;
  /** field with the extra client properties not covered in the schema. */
  properties?: InputMaybe<Scalars['Object']['input']>;
  /**
   * The redirect uri validation policy to use for this client.
   *
   * This value overrides the profile's setting for the default redirect uri validation policy.
   */
  redirect_uri_validation_policy_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * The client redirect URIs.
   * Mandatory if the client has the [CodeCapability].
   */
  redirect_uris?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Configuration for Refresh Tokens. If not set, no Refresh Tokens will be issued. */
  refresh_token?: InputMaybe<RefreshTokenInput>;
  /**
   * Enable request-object support where the client can send in a JWT
   * with the request parameters.
   * If set, a request object JWT MUST be provided by the client.
   */
  request_object?: InputMaybe<RequestObjectInput>;
  /**
   * If `true`, then all authorization responses need to be protected according to the
   * 'JWT Secured Authorization Response Mode for OAuth 2.0' (JARM) specification.
   *
   * Secured authorization responses requires the default-token-issuer on the profile to have
   * jwt-issuer-settings enabled, and the client must have the code or implicit capabilities enabled.
   */
  require_secured_authorization_response?: InputMaybe<Scalars['Boolean']['input']>;
  /** The scopes of this client. */
  scopes: Array<Scalars['String']['input']>;
  /**
   * The sector identifier that is used to derive the pairwise pseudonym from,
   * i.e. the pairwise pseudonym is defined for the pair of sector identifier and subject.
   *
   * Only used if `subject_type` is set to `pairwise`.
   */
  sector_identifier?: InputMaybe<Scalars['String']['input']>;
  /** The desired status of the client. */
  status?: InputMaybe<DatabaseClientStatus>;
  /**
   * Whether the client should issue pairwise pseudonym subject identifiers
   * or public identifiers.
   *
   * When set to `pairwise`, the client must have at least one redirect-uri configured,
   * or it must set a `sector_identifier` to use,
   * and MUST NOT have the `ResourceOwnerPasswordCredentialsCapability`.
   */
  subject_type?: InputMaybe<SubjectType>;
  /** Optional list of tags categorizing this client, thus allowing to easily filter clients in chosen categories. */
  tags?: InputMaybe<Array<Scalars['String']['input']>>;
  /** An absolute URL that refers to the terms of service of the client. */
  tos_uri?: InputMaybe<Scalars['String']['input']>;
  /** Enable client to perform user authentication. */
  user_authentication?: InputMaybe<UserAuthenticationInput>;
  /**
   * A token issuer with a purpose of userinfo.
   *
   * Enables support for returning userinfo as signed JWT.
   */
  userinfo_signed_issuer_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * Whether the port should be validated when a client is configured to redirect to the loopback interface.
   * Defaults to false because RFC-8252 (sec. 3) says the port should not be
   * validated and this does not generally reduces the security of local redirects.
   * This option can not be set when the profile enables redirect-uri validation policies.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  validate_port_on_loopback_interfaces?: InputMaybe<Scalars['Boolean']['input']>;
};

/** Client node. */
export type DatabaseClientEdge = {
  __typename?: 'DatabaseClientEdge';
  /** The item at the end of the edge. */
  node?: Maybe<DatabaseClient>;
};

/** Database client sort attributes. */
export enum DatabaseClientSortAttribute {
  /** Created. */
  Created = 'created',
  /** Last modified. */
  LastModified = 'lastModified',
  /** Client name. */
  Name = 'name'
}

/** Database client Sorting. */
export type DatabaseClientSorting = {
  /** Sort by attribute. */
  sortBy: DatabaseClientSortAttribute;
  /** Sort order. */
  sortOrder: SortOrder;
};

/** Status of an OAuth client. */
export enum DatabaseClientStatus {
  /** Active client */
  Active = 'ACTIVE',
  /** Inactive client */
  Inactive = 'INACTIVE',
  /** Revoked client */
  Revoked = 'REVOKED'
}

/** Database client update attributes. */
export type DatabaseClientUpdateFields = {
  /** The Time To Live for an access token. */
  access_token_ttl?: InputMaybe<Scalars['Long']['input']>;
  /**
   * Allow clients to register with the allow per request redirect uri setting.
   * Can only be enabled for the code flow with pushed authorization requests and when this setting
   * is allowed on the profile. Defaults to false.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  allow_per_request_redirect_uris?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * The optional list of URIs or URI-patterns that is allowed to embed the rendered pages inside
   * an iframe, be a trusted source or be used for CORS.
   */
  allowed_origins?: InputMaybe<Array<Scalars['String']['input']>>;
  /**
   * This URL is used if a request is made to the OAuth server without the parameters necessary
   * to initiate authentication.
   * In such a case, the user is redirected to this URL, so that a new, properly
   * formed, request can be made to bootstrap a new authentication transaction.
   */
  application_url?: InputMaybe<Scalars['String']['input']>;
  /**
   * The intended audiences for the token.
   * The first element is the default. If none are stipulated,
   * the ID of the client will be used as the audience.
   */
  audiences?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Client capabilities. A Client must have at least one capability. */
  capabilities?: InputMaybe<CapabilitiesInput>;
  /**
   * The mapper to use when adding claims to tokens.
   * The mapper decides what claims end up in which token or response.
   * The claims themselves are defined in the scope.
   * If not set, the default-mapper is used.
   */
  claim_mapper_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * Mechanism used by this client to authenticate.
   * One must be selected. For public clients, select a primary method
   * of `NoAuthentication`.
   */
  client_authentication?: InputMaybe<ClientAuthenticationInput>;
  /** A human readable description of the client. */
  description?: InputMaybe<Scalars['String']['input']>;
  /** Configuration for ID Tokens. */
  id_token?: InputMaybe<IdTokenInput>;
  /**
   * A logo of the client, that can shown in user interface templates.
   *
   * Must resolve to an image.
   */
  logo_uri?: InputMaybe<Scalars['String']['input']>;
  /** A human readable name of the client. */
  name?: InputMaybe<Scalars['String']['input']>;
  /** An absolute URL that refers to the privacy policy for the client. */
  policy_uri?: InputMaybe<Scalars['String']['input']>;
  /**
   * Field with the extra client properties not covered in the schema.
   *
   * Setting this value overwrites all client properties.
   */
  properties?: InputMaybe<Scalars['Object']['input']>;
  /**
   * The redirect uri validation policy to use for this client.
   *
   * This value overrides the profile's setting for the default redirect uri validation policy.
   */
  redirect_uri_validation_policy_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * The client redirect URIs.
   * Mandatory if the client has the [CodeCapability].
   */
  redirect_uris?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Configuration for Refresh Tokens. If not set, no Refresh Tokens will be issued. */
  refresh_token?: InputMaybe<RefreshTokenInput>;
  /**
   * Enable request-object support where the client can send in a JWT
   * with the request parameters.
   * If set, a request object JWT MUST be provided by the client.
   */
  request_object?: InputMaybe<RequestObjectInput>;
  /**
   * If `true`, then all authorization responses need to be protected according to the
   * 'JWT Secured Authorization Response Mode for OAuth 2.0' (JARM) specification.
   *
   * Secured authorization responses requires the default-token-issuer on the profile to have
   * jwt-issuer-settings enabled, and the client must have the code or implicit capabilities enabled.
   */
  require_secured_authorization_response?: InputMaybe<Scalars['Boolean']['input']>;
  /** The scopes of this client. */
  scopes?: InputMaybe<Array<Scalars['String']['input']>>;
  /**
   * The sector identifier that is used to derive the pairwise pseudonym from,
   * i.e. the pairwise pseudonym is defined for the pair of sector identifier and subject.
   *
   * Only used if `subject_type` is set to `pairwise`.
   */
  sector_identifier?: InputMaybe<Scalars['String']['input']>;
  /** The desired status of the client. */
  status?: InputMaybe<DatabaseClientStatus>;
  /**
   * Whether the client should issue pairwise pseudonym subject identifiers
   * or public identifiers.
   *
   * When set to `pairwise`, the client must have at least one redirect-uri configured,
   * or it must set a `sector_identifier` to use,
   * and MUST NOT have the `ResourceOwnerPasswordCredentialsCapability`.
   */
  subject_type?: InputMaybe<SubjectType>;
  /** Optional list of tags categorizing this client, thus allowing to easily filter clients in chosen categories. */
  tags?: InputMaybe<Array<Scalars['String']['input']>>;
  /** An absolute URL that refers to the terms of service of the client. */
  tos_uri?: InputMaybe<Scalars['String']['input']>;
  /** Enable client to perform user authentication. */
  user_authentication?: InputMaybe<UserAuthenticationInput>;
  /**
   * A token issuer with a purpose of userinfo.
   *
   * Enables support for returning userinfo as signed JWT.
   */
  userinfo_signed_issuer_id?: InputMaybe<Scalars['String']['input']>;
  /**
   * Whether the port should be validated when a client is configured to redirect to the loopback interface.
   * This option can not be set when the profile enables redirect-uri validation policies.
   * This setting is deprecated in favour of redirect-uri-validation-policies.
   */
  validate_port_on_loopback_interfaces?: InputMaybe<Scalars['Boolean']['input']>;
};

/** Input for the delete operation. */
export type DeleteDatabaseClientByIdInput = {
  /** The client to delete. */
  client_id: Scalars['ID']['input'];
};

/** Response of the delete operation. */
export type DeleteDatabaseClientPayload = {
  __typename?: 'DeleteDatabaseClientPayload';
  /** `true` if the client was successfully deleted. */
  deleted: Scalars['Boolean']['output'];
};

/** Disable client attestation */
export enum Disable {
  /** Disable client attestation */
  Disable = 'DISABLE'
}

/** DN Mutual TLS Authentication */
export type DnMutualTls = NameAndCa & {
  __typename?: 'DnMutualTls';
  /** The DN of the client certificate that the client must identify with. */
  client_dn: Scalars['String']['output'];
  /** RDNs to match. */
  rdns_to_match: Array<Scalars['String']['output']>;
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** DN Mutual TLS Authentication */
export type DnMutualTlsInput = {
  /** The DN of the client certificate that the client must identify with. */
  client_dn: Scalars['String']['input'];
  /** RDNs to match. */
  rdns_to_match: Array<Scalars['String']['input']>;
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['input']>;
};

/** DNs Mutual TLS Authentication */
export type DnsMutualTls = NameAndCa & {
  __typename?: 'DnsMutualTls';
  /**
   * The expected dNSName SAN entry in the certificate that the client
   * must identify with.
   */
  client_dns: Scalars['String']['output'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** DNs Mutual TLS Authentication */
export type DnsMutualTlsInput = {
  /**
   * The expected dNSName SAN entry in the certificate that the client
   * must identify with.
   */
  client_dns: Scalars['String']['input'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['input']>;
};

/** Email Mutual TLS Authentication */
export type EmailMutualTls = NameAndCa & {
  __typename?: 'EmailMutualTls';
  /**
   * The expected rfc822Name SAN entry in the certificate that the client
   * must identify with.
   */
  client_email: Scalars['String']['output'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** Email Mutual TLS Authentication */
export type EmailMutualTlsInput = {
  /**
   * The expected rfc822Name SAN entry in the certificate that the client
   * must identify with.
   */
  client_email: Scalars['String']['input'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['input']>;
};

/** HAAPI (Hypermedia authentication API) capability type */
export enum Haapi {
  /** HAAPI (Hypermedia authentication API) capability type */
  Haapi = 'HAAPI'
}

/**
 * Allows the client to use the hypermedia authentication API.
 *
 * When enabled, the client MUST also have the `CodeCapability` and optionally,
 * the `ImplicitCapability` capability (but no other capability types).
 */
export type HaapiCapability = {
  __typename?: 'HaapiCapability';
  /**
   * Client attestation to use.
   *
   * To allow a client to skip attestation, use the NoAttestation variant
   * and make sure that the client uses a strong authentication method.
   * It is not allowed to use NoAttestation with a public client.
   */
  client_attestation: ClientAttestation;
  /** Type of the HAAPI capability */
  type: Haapi;
  /**
   * Use an older version of the DPoP processing, which is not nonce-based.
   *
   * This may be required if the client uses an older version of the HAAPI SDK.
   * Refer to the HAAPI SDK documentation for details.
   */
  use_legacy_dpop: Scalars['Boolean']['output'];
};

/**
 * Allows the client to use the hypermedia authentication API.
 *
 * When enabled, the client MUST also have the `CodeCapability` and optionally,
 * the `ImplicitCapability` capability (but no other capability types).
 */
export type HaapiCapabilityInput = {
  /**
   * Client attestation to use.
   *
   * If not set, the client is allowed to use only authentication instead of client attestation to use HAAPI.
   * For this reason, if this is not set, the client must NOT set `client_authentication` to `NoAuthentication`.
   */
  client_attestation?: InputMaybe<ClientAttestationInput>;
  /** Type of the HAAPI capability */
  type: Haapi;
  /**
   * Use an older version of the DPoP processing, which is not nonce-based.
   *
   * This may be required if the client uses an older version of the HAAPI SDK.
   * Refer to the HAAPI SDK documentation for details.
   */
  use_legacy_dpop: Scalars['Boolean']['input'];
};

/** Configuration of ID tokens. */
export type IdToken = {
  __typename?: 'IdToken';
  /**
   * Enables ID Token Encryption as per JWE specification.
   *
   * The profile must enable id-token encryption before a client can configure it.
   */
  id_token_encryption?: Maybe<JweEncryption>;
  /** The Time to Live for an id token. If not set, the profile-setting is used. */
  id_token_ttl: Scalars['Long']['output'];
};

/** Configuration of ID tokens. */
export type IdTokenInput = {
  /**
   * Enables ID Token Encryption as per JWE specification."
   *
   * The profile must enable id-token encryption before a client can configure it.
   */
  id_token_encryption?: InputMaybe<JweEncryptionInput>;
  /** The Time to Live for an id token. If not set, the profile-setting is used. */
  id_token_ttl?: InputMaybe<Scalars['Long']['input']>;
};

/** Implicit flow capability type */
export enum Implicit {
  /** Implicit flow capability type */
  Implicit = 'IMPLICIT'
}

/** Implicit capability */
export type ImplicitCapability = {
  __typename?: 'ImplicitCapability';
  /** Type of the implicit capability */
  type: Implicit;
};

/** Implicit capability */
export type ImplicitCapabilityInput = {
  /** Type of the implicit capability */
  type?: InputMaybe<Implicit>;
};

/** Token Introspection capability type */
export enum Introspection {
  /** Token Introspection capability type */
  Introspection = 'INTROSPECTION'
}

/**
 * Allows the client to use token introspection.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type IntrospectionCapability = {
  __typename?: 'IntrospectionCapability';
  /** Type of the token introspection capability */
  type: Introspection;
};

/**
 * Allows the client to use token introspection.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type IntrospectionCapabilityInput = {
  /** Type of the token introspection capability */
  type: Introspection;
};

/** IOS client attestation */
export enum Ios {
  /** IOS client attestation */
  Ios = 'IOS'
}

/** IOS client attestation configuration */
export type IosAttestation = {
  __typename?: 'IosAttestation';
  /** IOS App ID that should be allowed to perform client attestation */
  app_id: Scalars['String']['output'];
  /** Attestation policy ID */
  policy_id?: Maybe<Scalars['String']['output']>;
  /** Type of client attestation */
  type: Ios;
};

/** IOS client attestation configuration */
export type IosAttestationInput = {
  /** IOS App ID that should be allowed to perform client attestation */
  app_id: Scalars['String']['input'];
  /** Attestation policy ID */
  policy_id?: InputMaybe<Scalars['String']['input']>;
  /** Type of client attestation */
  type: Ios;
};

/** IP Mutual TLS Authentication */
export type IpMutualTls = NameAndCa & {
  __typename?: 'IpMutualTls';
  /**
   * The expected IP address in either dotted decimal notation (for IPv4)
   * or colon-delimited hexadecimal (for IPv6) that is expected to be present as
   * an iPAddress SAN entry in the certificate that the client must identify with.
   */
  client_ip: Scalars['String']['output'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** IP Mutual TLS Authentication */
export type IpMutualTlsInput = {
  /**
   * The expected IP address in either dotted decimal notation (for IPv4)
   * or colon-delimited hexadecimal (for IPv6) that is expected to be present as
   * an iPAddress SAN entry in the certificate that the client must identify with.
   */
  client_ip: Scalars['String']['input'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['input']>;
};

/** JWE encryption configuration */
export type JweEncryption = {
  __typename?: 'JweEncryption';
  /** Supported content encryption algorithms, present as 'enc' in JWE header. */
  allowed_content_encryption_alg: ContentEncryptionAlgorithm;
  /** Algorithms supported to encrypt the content encryption key, present as 'alg' in JWE header. */
  allowed_key_management_alg: AsymmetricKeyManagementAlgorithm;
  /** Encryption key ID */
  encryption_key_id: Scalars['String']['output'];
};

/** JWE encryption configuration */
export type JweEncryptionInput = {
  /** Supported content encryption algorithms, present as 'enc' in JWE header. */
  allowed_content_encryption_alg: ContentEncryptionAlgorithm;
  /** Algorithms supported to encrypt the content encryption key, present as 'alg' in JWE header. */
  allowed_key_management_alg: AsymmetricKeyManagementAlgorithm;
  /** Encryption key ID */
  encryption_key_id: Scalars['String']['input'];
};

/** A key present in a JWKS referenced by an URI, accessed via an optional HTTP client ID. */
export type JwksUri = {
  __typename?: 'JwksUri';
  /** The optional HTTP client used to retrieve the JWKS. */
  http_client_id?: Maybe<Scalars['String']['output']>;
  /** The JWKS URI. */
  uri: Scalars['String']['output'];
};

/** A key present in a JWKS referenced by an URI, accessed via an optional HTTP client ID. */
export type JwksUriInput = {
  /** The optional HTTP client used to retrieve the JWKS. */
  http_client_id?: InputMaybe<Scalars['String']['input']>;
  /** The JWKS URI. */
  uri: Scalars['String']['input'];
};

/** JWT assertion configuration */
export type JwtAssertion = {
  __typename?: 'JwtAssertion';
  /** Allow a client to reuse the same JWT assertion to make multiple token requests. */
  allow_reuse: Scalars['Boolean']['output'];
  /**
   * When set, a JWT that is used as assertion must have an issuer claim that matches
   * the configured value.
   */
  issuer?: Maybe<Scalars['String']['output']>;
  /**
   * The assertion capability must be enabled in the profile with allowed algorithms
   * for the selected signing option.
   */
  signing: JwtSigning;
};

/** JWT assertion configuration */
export type JwtAssertionInput = {
  /** Allow a client to reuse the same JWT assertion to make multiple token requests. */
  allow_reuse?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * When set, a JWT that is used as assertion must have an issuer claim that matches
   * the configured value.
   */
  issuer?: InputMaybe<Scalars['String']['input']>;
  /**
   * The assertion capability must be enabled in the profile with allowed algorithms
   * for the selected signing option.
   */
  signing: JwtSigningInput;
};

/** JWT signing configuration */
export type JwtSigning = AsymmetricKey | JwksUri | SymmetricKey;

/** This is an union type. Only one of the fields must be set. */
export type JwtSigningInput = {
  /** Asymmetric key */
  asymmetric_key?: InputMaybe<AsymmetricKeyInput>;
  /** JWKS URI */
  jwks?: InputMaybe<JwksUriInput>;
  /** Symmetric key */
  symmetric_key?: InputMaybe<SymmetricKeyInput>;
};

/** Metadata about client. */
export type Meta = {
  __typename?: 'Meta';
  /** Instant the resource was created (in epoch-seconds). */
  created: Scalars['Long']['output'];
  /** Instant the resource was last modified (in epoch-seconds). */
  lastModified: Scalars['Long']['output'];
};

/** Mutation definitions. */
export type Mutation = {
  __typename?: 'Mutation';
  /**
   * Creates a client.
   * The full client is returned with potential modifications
   * depending on the server configuration.
   */
  createDatabaseClient?: Maybe<CreateDatabaseClientPayload>;
  /**
   * Deletes a client.
   * If a client with the given ID does not exist, an error occurs.
   */
  deleteDatabaseClientById?: Maybe<DeleteDatabaseClientPayload>;
  /** Updates the owner of a given database client. */
  setDatabaseClientOwnerById?: Maybe<SetDatabaseClientOwnerPayload>;
  /**
   * Sets the status of the client with the provided ID.
   * If the client does not exist, a null result is returned.
   */
  setDatabaseClientStatusById?: Maybe<SetDatabaseClientStatusPayload>;
  /**
   * Updates a client.
   * Only the provided fields are updated, missing fields are not removed unless an explicit
   * `null` value is sent.
   * Complex fields are NOT merged, i.e. they are replaced completely if provided.
   * For example, for a list field:
   * * If the list field is not provided: the current list value is left untouched
   * * If the list field is provided with a null or empty value: the current list value is removed
   * * If a non-empty list field is provided: the current list value is replaced.
   * If a client with the given ID does not exist, an error occurs.
   */
  updateDatabaseClientById?: Maybe<UpdateDatabaseClientPayload>;
};


/** Mutation definitions. */
export type MutationCreateDatabaseClientArgs = {
  input: CreateDatabaseClientInput;
};


/** Mutation definitions. */
export type MutationDeleteDatabaseClientByIdArgs = {
  input: DeleteDatabaseClientByIdInput;
};


/** Mutation definitions. */
export type MutationSetDatabaseClientOwnerByIdArgs = {
  input: SetDatabaseClientOwnerByIdInput;
};


/** Mutation definitions. */
export type MutationSetDatabaseClientStatusByIdArgs = {
  input: SetDatabaseClientStatusByIdInput;
};


/** Mutation definitions. */
export type MutationUpdateDatabaseClientByIdArgs = {
  input: UpdateDatabaseClientByIdInput;
};

/** Mutual TLS Authentication */
export type MutualTls = DnMutualTls | DnsMutualTls | EmailMutualTls | IpMutualTls | PinnedCertificate | TrustedCaOnly | UriMutualTls;

/** Enable client authentication through mutual-tls by-proxy. */
export type MutualTlsByProxyVerifier = {
  __typename?: 'MutualTlsByProxyVerifier';
  /**
   * Enable client authentication through mutual-tls by-proxy.
   *
   * Mutual-tls by-proxy must be configured in the profile.
   */
  mutual_tls_by_proxy: MutualTls;
};

/** This is an union type. Only one of the fields must be set. */
export type MutualTlsInput = {
  /** DN Mutual TLS Authentication */
  dn?: InputMaybe<DnMutualTlsInput>;
  /** DNs Mutual TLS Authentication */
  dns?: InputMaybe<DnsMutualTlsInput>;
  /** Email Mutual TLS Authentication */
  email?: InputMaybe<EmailMutualTlsInput>;
  /** IP Mutual TLS Authentication */
  ip?: InputMaybe<IpMutualTlsInput>;
  /** The client certificate that must be used to authenticate the client. */
  pinned_certificate?: InputMaybe<PinnedCertificateInput>;
  /**
   * The CA's that can be the issuer of the client certificate that can be accepted
   * to authenticate this client.
   * If empty, then all profile certificates may be used to authenticate the client.
   */
  trusted_cas?: InputMaybe<Array<Scalars['String']['input']>>;
  /** URI Mutual TLS Authentication */
  uri?: InputMaybe<UriMutualTlsInput>;
};

/** Enable client authentication through direct mutual-tls. */
export type MutualTlsVerifier = {
  __typename?: 'MutualTlsVerifier';
  /**
   * Enable client authentication through direct mutual-tls.
   *
   * Mutual-tls must be configured in the profile (without the use of a proxy).
   */
  mutual_tls: MutualTls;
};

/** Abstract type to authenticate client through Mutual-TLS. */
export type NameAndCa = {
  /**
   * The CA's that can be the issuer of the client certificate that can be accepted
   * to authenticate this client.
   * If empty, then all profile certificates may be used to authenticate the client.
   */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** Disable client attestation */
export type NoAttestation = {
  __typename?: 'NoAttestation';
  /** Type of client attestation */
  type: Disable;
};

/** No attestation. */
export type NoAttestationInput = {
  /** Type of no attestation. */
  type: Disable;
};

/** Value used to indicate no authentication is required. */
export enum NoAuth {
  /** Value used to indicate no authentication is required. */
  NoAuth = 'no_auth'
}

/** No Authentication configuration for public clients. */
export type NoAuthentication = {
  __typename?: 'NoAuthentication';
  /**
   * When no_authentication is selected, the client is a public client.
   *
   * Can only be used for clients that requests tokens, and only makes sense if they use the token endpoint
   * (i.e. MUST use the code flow).
   */
  no_authentication: NoAuth;
};

/** Information about pagination in a connection */
export type PageInfo = {
  __typename?: 'PageInfo';
  /** When paginating forwards, the cursor to continue */
  endCursor?: Maybe<Scalars['String']['output']>;
  /** When paginating forwards, are there more items? */
  hasNextPage: Scalars['Boolean']['output'];
};

/** Pinned Certificate Mutual TLS Authentication */
export type PinnedCertificate = {
  __typename?: 'PinnedCertificate';
  /** The ID of a client certificate that must be used to authenticate the client. */
  client_certificate_id: Scalars['String']['output'];
};

/** Pinned Certificate Mutual TLS Authentication */
export type PinnedCertificateInput = {
  /** The ID of a client certificate that must be used to authenticate the client. */
  client_certificate_id: Scalars['String']['input'];
};

/**
 * Proof Key for Code Exchange (RFC 7636 - PKCE) is a measure for preventing authorization code interception.
 * This is an attack on client systems that allow a malicious application to register itself as a handler for
 * the custom scheme utilized by the legitimate app in the Authorization Code Grant flow.
 */
export type ProofKey = {
  __typename?: 'ProofKey';
  /** Disallow the PLAIN challenge method */
  disallow_challenge_method_plain: Scalars['Boolean']['output'];
  /** Disallow the S256 challenge method */
  disallow_challenge_method_s256: Scalars['Boolean']['output'];
  /**
   * Enforces this client to provide a proof key challenge and -verifier when performing
   * the Authorization Code Grant flow.
   */
  require_proof_key: Scalars['Boolean']['output'];
};

/**
 * Proof Key for Code Exchange (RFC 7636 - PKCE) is a measure for preventing authorization code interception.
 * This is an attack on client systems that allow a malicious application to register itself as a handler for
 * the custom scheme utilized by the legitimate app in the Authorization Code Grant flow.
 */
export type ProofKeyInput = {
  /** Disallow the PLAIN challenge method */
  disallow_challenge_method_plain?: InputMaybe<Scalars['Boolean']['input']>;
  /** Disallow the S256 challenge method */
  disallow_challenge_method_s256?: InputMaybe<Scalars['Boolean']['input']>;
  /**
   * Enforces this client to provide a proof key challenge and -verifier when performing
   * the Authorization Code Grant flow.
   */
  require_proof_key: Scalars['Boolean']['input'];
};

/** Query definitions. */
export type Query = {
  __typename?: 'Query';
  /** Gets dynamically registered client by given client id */
  databaseClientById?: Maybe<DatabaseClient>;
  /**
   * Gets all database clients using the provided querying parameters.
   *
   * Only clients satisfying ALL provided arguments will be returned.
   */
  databaseClients: DatabaseClientConnection;
};


/** Query definitions. */
export type QueryDatabaseClientByIdArgs = {
  id: Scalars['ID']['input'];
};


/** Query definitions. */
export type QueryDatabaseClientsArgs = {
  activeClientsOnly?: InputMaybe<Scalars['Boolean']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  clientName?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  sorting?: InputMaybe<DatabaseClientSorting>;
  tags?: InputMaybe<Array<Scalars['String']['input']>>;
};

/** Configuration of refresh tokens. */
export type RefreshToken = {
  __typename?: 'RefreshToken';
  /**
   * When set, the refresh_token_ttl is used to set the expiration of new refresh tokens,
   * until this max value is reached.
   */
  refresh_token_max_rolling_lifetime?: Maybe<Scalars['Long']['output']>;
  /**
   * The Time To Live for a Refresh token in seconds.
   * If set to 0, no Refresh Tokens will be issued.
   */
  refresh_token_ttl: Scalars['Long']['output'];
  /**
   * Defines if refresh tokens are created on every refresh or if they are kept.
   * When set, this takes precedence over profile setting (reuse-refresh-tokens),
   * when not set profile setting applies.
   */
  reuse_refresh_tokens?: Maybe<Scalars['Boolean']['output']>;
};

/** Configuration of refresh tokens. */
export type RefreshTokenInput = {
  /**
   * When set, the refresh_token_ttl is used to set the expiration of new refresh tokens,
   * until this max value is reached.
   */
  refresh_token_max_rolling_lifetime?: InputMaybe<Scalars['Long']['input']>;
  /** The Time To Live for a Refresh token. */
  refresh_token_ttl: Scalars['Long']['input'];
  /**
   * Defines if refresh tokens are created on every refresh or if they are kept.
   * When set, this takes precedence over profile setting (reuse-refresh-tokens),
   * when not set profile setting applies.
   */
  reuse_refresh_tokens?: InputMaybe<Scalars['Boolean']['input']>;
};

/** Request Object configuration */
export type RequestObject = {
  __typename?: 'RequestObject';
  /**
   * If set to true, then unsigned request objects sent by-value will be accepted.
   *
   * Enabling unsigned request objects requires the 'none' algorithm to be in the profile's
   * request object allowed algorithms.
   */
  allow_unsigned_for_by_value?: Maybe<Scalars['Boolean']['output']>;
  /** Enable the use of request object that are sent by-reference using the request_uri parameter. */
  by_reference?: Maybe<ByRefRequestObject>;
  /**
   * The issuer of the request object's JWT.
   *
   * If the issuer is not explicitly set, it must be the same value as the client_id of the client
   * that makes the request.
   */
  request_jwt_issuer?: Maybe<Scalars['String']['output']>;
  /**
   * A public key that corresponds to the private key that the issuer of
   * the request object JWT used to sign the JWT.
   *
   * Request object support must be enabled in the profile with at least one algorithm other than `none`.
   */
  request_jwt_signature_verification_key?: Maybe<Scalars['String']['output']>;
};

/** Request Object configuration */
export type RequestObjectInput = {
  /**
   * If set to true, then unsigned request objects sent by-value will be accepted.
   *
   * Enabling unsigned request objects requires the 'none' algorithm to be in the profile's
   * request object allowed algorithms.
   */
  allow_unsigned_for_by_value?: InputMaybe<Scalars['Boolean']['input']>;
  /** Enable the use of request object that are sent by-reference using the request_uri parameter. */
  by_reference?: InputMaybe<ByRefRequestObjectInput>;
  /**
   * The issuer of the request object's JWT.
   *
   * If the issuer is not explicitly set, it must be the same value as the client_id of the client
   * that makes the request.
   */
  request_jwt_issuer?: InputMaybe<Scalars['String']['input']>;
  /**
   * A public key that corresponds to the private key that the issuer of
   * the request object JWT used to sign the JWT.
   *
   * Request object support must be enabled in the profile with at least one algorithm other than `none`.
   */
  request_jwt_signature_verification_key?: InputMaybe<Scalars['String']['input']>;
};

/** Resource-owner password credentials flow capability type */
export enum ResourceOwnerPasswordCredentials {
  /** Resource-owner password credentials flow capability type */
  Ropc = 'ROPC'
}

/** Resource owner password credentials capability */
export type ResourceOwnerPasswordCredentialsCapability = {
  __typename?: 'ResourceOwnerPasswordCredentialsCapability';
  /** The optional credential manager to use when authenticating the user using Resource Owner Password Credentials. */
  credential_manager_id?: Maybe<Scalars['String']['output']>;
  /** Type of the resource-owner password credentials capability */
  type: ResourceOwnerPasswordCredentials;
};

/** Resource owner password credentials capability */
export type ResourceOwnerPasswordCredentialsCapabilityInput = {
  /** The optional credential manager to use when authenticating the user using Resource Owner Password Credentials. */
  credential_manager_id?: InputMaybe<Scalars['String']['input']>;
  /** Type of the resource-owner password credentials capability */
  type?: InputMaybe<ResourceOwnerPasswordCredentials>;
};

/** Secret to be used by a client */
export type Secret = {
  __typename?: 'Secret';
  /**
   * "
   * A password used by the client.
   *
   * Basic and form post Client authentication must be enabled in the profile.
   *
   * Only the hashed secret is ever returned.
   */
  secret: Scalars['String']['output'];
};

/** Secret to be used by a client */
export type SecretInput = {
  /**
   * "
   * A password used by the client.
   *
   * Basic and form post Client authentication must be enabled in the profile.
   *
   * The secret may already be hashed, but if it's not, it is hashed before being stored in a data source.
   */
  secret: Scalars['String']['input'];
};

/** Input of `setDatabaseClientOwnerById` mutation */
export type SetDatabaseClientOwnerByIdInput = {
  /** The client to update. */
  client_id: Scalars['ID']['input'];
  /** The subject of the new owner. */
  owner: Scalars['String']['input'];
};

/** Result of `setDatabaseClientOwnerById` mutation */
export type SetDatabaseClientOwnerPayload = {
  __typename?: 'SetDatabaseClientOwnerPayload';
  /** The updated client. */
  client: DatabaseClient;
};

/** Input of the set-client-status operation. */
export type SetDatabaseClientStatusByIdInput = {
  /** Client ID. */
  client_id: Scalars['ID']['input'];
  /** The desired status of the client. */
  status: DatabaseClientStatus;
};

/** Result of the `setClientStatus` mutation. */
export type SetDatabaseClientStatusPayload = {
  __typename?: 'SetDatabaseClientStatusPayload';
  /** The updated client. */
  client: DatabaseClient;
};

/** Sort attribute. */
export enum SortAttribute {
  /** Created. */
  Created = 'created',
  /** Last modified. */
  LastModified = 'lastModified'
}

/** Sort order. */
export enum SortOrder {
  /** Ascending */
  Ascending = 'ASCENDING',
  /** Descending */
  Descending = 'DESCENDING'
}

/** Sorting. */
export type Sorting = {
  /** Sort by attribute. */
  sortBy: SortAttribute;
  /** Sort order. */
  sortOrder: SortOrder;
};

/**
 * Whether the client should issue pairwise pseudonym subject identifiers
 * or public identifiers.
 */
export enum SubjectType {
  /** Pairwise. */
  Pairwise = 'pairwise',
  /** Public. */
  Public = 'public'
}

/** Symmetric key configuration */
export type SymmetricKey = {
  __typename?: 'SymmetricKey';
  /**
   * A symmetric key that the client will use to sign or integrity protect a token with
   * to authenticate itself.
   *
   * Symmetrically signed JWT Client authentication must be enabled in the profile.
   *
   * The symmetric key is sent in clear test. However, access to it can be managed by configuring an Attributes
   * Authorization Manager disallowing access to this attribute.
   *
   * Note that the symmetric key is encrypted when the database client is stored into a repository.
   */
  symmetric_key: Scalars['String']['output'];
};

/** Symmetric key configuration */
export type SymmetricKeyInput = {
  /**
   * A symmetric key that the client will use to sign or integrity protect a token with
   * to authenticate itself.
   *
   * Symmetrically signed JWT Client authentication must be enabled in the profile.
   *
   * Note that the symmetric key is encrypted when the database client is stored into a repository.
   */
  symmetric_key: Scalars['String']['input'];
};

/** Token exchange capability type */
export enum TokenExchange {
  /** Token exchange capability type */
  TokenExchange = 'TOKEN_EXCHANGE'
}

/**
 * Allows the client to use exchange tokens for other tokens.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type TokenExchangeCapability = {
  __typename?: 'TokenExchangeCapability';
  /** Type of the token exchange capability */
  type: TokenExchange;
};

/**
 * Allows the client to use exchange tokens for other tokens.
 *
 * When enabled, the client must NOT set `client_authentication` to `NoAuthentication`.
 */
export type TokenExchangeCapabilityInput = {
  /** Type of the token exchange capability */
  type: TokenExchange;
};

/** Trusted CA (only) Mutual TLS Authentication */
export type TrustedCaOnly = NameAndCa & {
  __typename?: 'TrustedCaOnly';
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** Input of the update operation. */
export type UpdateDatabaseClientByIdInput = {
  /** The client to update. */
  client_id: Scalars['ID']['input'];
  /** The fields to update. */
  fields: DatabaseClientUpdateFields;
};

/** Response of the update operation. */
export type UpdateDatabaseClientPayload = {
  __typename?: 'UpdateDatabaseClientPayload';
  /** The updated client. */
  client: DatabaseClient;
};

/** URI Mutual TLS Authentication */
export type UriMutualTls = NameAndCa & {
  __typename?: 'UriMutualTls';
  /**
   * The expected uniformResourceIdentifier SAN entry in the certificate
   * that the client must identify with.
   */
  client_uri: Scalars['String']['output'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['output']>;
};

/** URI Mutual TLS Authentication */
export type UriMutualTlsInput = {
  /**
   * The expected uniformResourceIdentifier SAN entry in the certificate
   * that the client must identify with.
   */
  client_uri: Scalars['String']['input'];
  /** The CAs trusted by this client. If empty, all of the CAs configured in the server are used. */
  trusted_cas: Array<Scalars['String']['input']>;
};

/** User authentication configuration */
export type UserAuthentication = {
  __typename?: 'UserAuthentication';
  /** The list of allowed authenticators for this client. If empty, all authenticators are allowed. */
  allowed_authenticators: Array<Scalars['String']['output']>;
  /**
   * The optional list of URIs that is allowed for the client to use as
   * post logout redirect uri. Requires OpenId Connect to be enabled.
   */
  allowed_post_logout_redirect_uris: Array<Scalars['String']['output']>;
  /** The list of authenticator-filters for this client. */
  authenticator_filters: Array<Scalars['String']['output']>;
  /**
   * Optional uri of the client that is called upon user logout when attempting
   * back channel logout. Requires OpenId Connect to be enabled.
   */
  backchannel_logout_uri?: Maybe<Scalars['String']['output']>;
  /**
   * When set, the user is asked to accept the delegation via a consent screen. This applies
   * to all interactive flows (i.e. code, implicit, assisted token and device authorization flow).
   */
  consent?: Maybe<UserConsent>;
  /** Information that will be displayed to the user when authenticating the client */
  context_info: Scalars['String']['output'];
  /** Whether user authentication is forced at all times. */
  force_authentication?: Maybe<Scalars['Boolean']['output']>;
  /** Optional maximum age in seconds after which re-authentication must take place. */
  freshness?: Maybe<Scalars['Long']['output']>;
  /**
   * Optional uri of the client that is called upon user logout when attempting
   * front channel logout. Requires OpenId Connect to be enabled.
   */
  frontchannel_logout_uri?: Maybe<Scalars['String']['output']>;
  /**
   * The HTTP client that will be used when delivering the logout token to
   * the backchannel logout uri.
   */
  http_client_id?: Maybe<Scalars['String']['output']>;
  /** Optional override for default locale. */
  locale?: Maybe<Scalars['String']['output']>;
  /** A list of named claims that must be required by the authenticator when authenticating the user. */
  required_claims: Array<Scalars['String']['output']>;
  /** Optional override for template area */
  template_area?: Maybe<Scalars['String']['output']>;
};

/** User authentication configuration */
export type UserAuthenticationInput = {
  /** The list of allowed authenticators for this client. If not set, all authenticators are allowed. */
  allowed_authenticators?: InputMaybe<Array<Scalars['String']['input']>>;
  /**
   * The optional list of URIs that is allowed for the client to use as
   * post logout redirect uri. Requires OpenId Connect to be enabled.
   */
  allowed_post_logout_redirect_uris?: InputMaybe<Array<Scalars['String']['input']>>;
  /** The list of authenticator-filters for this client. */
  authenticator_filters?: InputMaybe<Array<Scalars['String']['input']>>;
  /**
   * Optional uri of the client that is called upon user logout when attempting
   * back channel logout. Requires OpenId Connect to be enabled.
   */
  backchannel_logout_uri?: InputMaybe<Scalars['String']['input']>;
  /**
   * When set, the user is asked to accept the delegation via a consent screen. This applies
   * to all interactive flows (i.e. code, implicit, assisted token and device authorization flow).
   */
  consent?: InputMaybe<ConsentInput>;
  /** Information that will be displayed to the user when authenticating the client */
  context_info: Scalars['String']['input'];
  /** Optional default setting whether user authentication is forced at all times. */
  force_authentication?: InputMaybe<Scalars['Boolean']['input']>;
  /** Optional maximum age in seconds after which re-authentication must take place. */
  freshness?: InputMaybe<Scalars['Long']['input']>;
  /**
   * Optional uri of the client that is called upon user logout when attempting
   * front channel logout. Requires OpenId Connect to be enabled.
   */
  frontchannel_logout_uri?: InputMaybe<Scalars['String']['input']>;
  /**
   * The HTTP client that will be used when delivering the logout token to
   * the backchannel logout uri.
   */
  http_client_id?: InputMaybe<Scalars['String']['input']>;
  /** Optional override for default locale. */
  locale?: InputMaybe<Scalars['String']['input']>;
  /** A list of named claims that must be required by the authenticator when authenticating the user. */
  required_claims?: InputMaybe<Array<Scalars['String']['input']>>;
  /** Optional override for template area */
  template_area?: InputMaybe<Scalars['String']['input']>;
};

/** User consent configuration */
export type UserConsent = {
  __typename?: 'UserConsent';
  /**
   * When enabled, the user is allowed to deselect optional scopes or claims when
   * asked for consent.
   */
  allow_deselection: Scalars['Boolean']['output'];
  /**
   * The consentors usable with this client.
   *
   * If empty, then all profile consentors will be usable.
   */
  consentors: Array<Scalars['String']['output']>;
  /** When enabled, the built-in consent screen will not be shown and only the consentors will run. */
  only_consentors: Scalars['Boolean']['output'];
};

/** Web client attestation */
export enum Web {
  /** Web client attestation */
  Web = 'WEB'
}

/** Web client attestation configuration */
export type WebAttestation = {
  __typename?: 'WebAttestation';
  /** Attestation policy ID */
  policy_id?: Maybe<Scalars['String']['output']>;
  /** Type of client attestation */
  type: Web;
};

/** Web client attestation configuration */
export type WebAttestationInput = {
  /** Attestation policy ID */
  policy_id?: InputMaybe<Scalars['String']['input']>;
  /** Type of client attestation */
  type: Web;
};
