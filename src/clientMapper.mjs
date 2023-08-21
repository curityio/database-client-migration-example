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

export function mapStaticClientToDatabaseClient(client) {

    moveProperty(client, ['access-token-ttl'], ['access_token_ttl']);
    moveProperty(client, ['allowed-origins'], ['allowed_origins']);
    moveProperty(client, ['application-url'], ['application_url']);
    moveProperty(client, ['audience'], ['audiences']);
    moveProperty(client, ['claims-mapper'], ['claim_mapper_id']);

    moveProperty(client, ['capabilities', 'assisted-token'], ['capabilities', 'assisted_token', 'type']);
    moveProperty(client, ['capabilities', 'code'], ['capabilities', 'code', 'type']);
    moveProperty(client, ['capabilities', 'introspection'], ['capabilities', 'introspection', 'type']);

    moveProperty(client, ['id'], ['client_id']);
    moveProperty(client, ['redirect-uris'], ['redirect_uris']);
    moveProperty(client, ['scope'], ['scopes']);
    moveProperty(client, ['secret'], ['client_authentication', 'primary', 'secret', 'secret']);
    moveProperty(client, ['user-authentication'], ['user_authentication']);
    moveProperty(client, ['validate-port-on-loopback-interfaces'], ['validate_port_on_loopback_interfaces']);

    if (client?.capabilities?.code?.type) {
        client.capabilities.code.type = 'CODE';
    }
    if (client?.capabilities?.introspection?.type) {
        client.capabilities.introspection.type = 'INTROSPECTION';
    }
    
    if (client?.validate_port_on_loopback_interfaces) {
        delete client.validate_port_on_loopback_interfaces;
    }
    if (client?.user_authentication) {
        delete client.user_authentication;
    }

    //client.validate_port_on_loopback_interfaces.value = true
    //client.user_authentication = undefined;

    return client;
}

/*
export function adaptDatabaseClientToConfigClient(client) {

    return client
      ? {
          'asymmetric-key': client.client_authentication?.primary.asymmetric_key_id || undefined,
          'client-authentication-method': getDatabaseClientAuthenticationMethod(client.client_authentication?.primary),
          'client-name': client.name || undefined,
          'credential-manager': client.client_authentication?.primary.credential_manager_id || undefined,
          'id-token-ttl': client.id_token?.id_token_ttl,
          'no-authentication': !!client.client_authentication?.primary.no_authentication,
          'privacy-policy-url': client.policy_uri || undefined,
          'redirect-uri-validation-policy': client.redirect_uri_validation_policy_id || undefined,
          'redirect-uris': client.redirect_uris || undefined,
          'refresh-token-max-rolling-lifetime': client.refresh_token?.refresh_token_max_rolling_lifetime || 'disabled',
          'refresh-token-ttl': client.refresh_token?.refresh_token_ttl || 'disabled',
          'require-secured-authorization-response': client.require_secured_authorization_response ? [null] : undefined,
          'reuse-refresh-tokens': client.refresh_token?.reuse_refresh_tokens || undefined,
          'signed-userinfo': getSignedUserInfo(client.userinfo_signed_issuer_id),
          'symmetric-key': client.client_authentication?.primary.symmetric_key || undefined,
          'terms-of-service-url': client.tos_uri || undefined,
          'validate-port-on-loopback-interfaces': client.validate_port_on_loopback_interfaces || true,
          attestation: getClientAttestation(client.capabilities?.haapi?.client_attestation),
          audience: client.audiences,
          description: client.description || undefined,
          enabled: client.status === 'ACTIVE',
          id: client.client_id,
          logo: client.logo_uri || undefined,
          scope: client.scopes,
          secret: client.client_authentication?.primary?.secret,
          capabilities: {
            ...(client.capabilities?.assisted_token?.type && { 'assisted-token': [null] }),
            ...(client.capabilities?.code?.type && {
              code: {
                'require-pushed-authorization-requests': client.capabilities.code?.require_pushed_authorization_request
                  ? {
                      'allow-per-request-redirect-uris': client.allow_per_request_redirect_uris || undefined,
                    }
                  : undefined,
              },
            }),
            ...(client.capabilities?.client_credentials?.type && { 'client-credentials': [null] }),
            ...(client.capabilities?.resource_owner_password?.type && { 'resource-owner-password-credentials': {} }),
            ...(client.capabilities?.token_exchange?.type && { 'token-exchange': [null] }),
            ...(client.capabilities?.implicit?.type && { implicit: [null] }),
            ...(client.capabilities?.introspection?.type && { introspection: [null] }),
            ...(client.capabilities?.assertion?.type && {
              assertion: {
                jwt: {
                  'allow-reuse': client.capabilities.assertion.jwt?.allow_reuse,
                  trust: {
                    issuer: client.capabilities.assertion.jwt.issuer || undefined,
                    'asymmetric-signing-key': client.capabilities.assertion.jwt.signing.asymmetric_key_id,
                    'jwks-uri': client.capabilities.assertion.jwt.signing.jwks
                      ? {
                          uri: client.capabilities.assertion.jwt.signing.jwks?.uri,
                          'http-client': client.capabilities.assertion.jwt.signing.jwks?.http_client_id || undefined,
                        }
                      : undefined,
                  },
                },
              },
            }),
            ...(client.capabilities?.haapi?.type && {
              haapi: {
                'use-legacy-dpop': client.capabilities.haapi.use_legacy_dpop,
                'allow-without-attestation': false,
              },
            }),
            ...(client.capabilities?.backchannel && {
              'backchannel-authentication': {
                'allowed-authenticators': client.capabilities.backchannel.allowed_backchannel_authenticators,
              },
            }),
          },
          'id-token-encryption': client.id_token?.id_token_encryption
            ? {
                'content-encryption-algorithm': client.id_token.id_token_encryption.allowed_content_encryption_alg,
                'encryption-key': client.id_token.id_token_encryption.encryption_key_id,
                'key-management-algorithm': client.id_token.id_token_encryption.allowed_key_management_alg,
              }
            : undefined,
          'proof-key': {
            'require-proof-key': client.capabilities?.code?.proof_key?.require_proof_key || false,
            'disallowed-proof-key-challenge-methods': client.capabilities?.code
              ? getDisallowedProofKeyChallengeMethods(client.capabilities?.code.proof_key as ProofKey)
              : [],
          },
          'use-pairwise-subject-identifiers':
            client.subject_type === 'pairwise'
              ? {
                  'sector-identifier': client.sector_identifier || undefined,
                }
              : undefined,
          'user-authentication': client.user_authentication
            ? {
                'allowed-authenticators': client.user_authentication.allowed_authenticators,
                'allowed-post-logout-redirect-uris': client.user_authentication.allowed_post_logout_redirect_uris,
                'authenticator-filters': client.user_authentication.authenticator_filters,
                'backchannel-logout-uri': client.user_authentication.backchannel_logout_uri || undefined,
                'context-info': client.user_authentication.context_info,
                'force-authn': client.user_authentication.force_authentication || undefined,
                'frontchannel-logout-uri': client.user_authentication.frontchannel_logout_uri || undefined,
                'http-client': client.user_authentication.http_client_id || undefined,
                'required-claims': client.user_authentication.required_claims,
                'template-area': client.user_authentication.template_area || undefined,
                freshness: client.user_authentication.freshness || undefined,
                locale: client.user_authentication.locale || undefined,
              }
            : undefined,
          'request-object': client.request_object
            ? {
                'allow-unsigned-for-by-value': client.request_object.allow_unsigned_for_by_value,
                'signature-verification-key': client.request_object.request_jwt_signature_verification_key || undefined,
                issuer: client.request_object.request_jwt_issuer || undefined,
                'by-reference': client.request_object.by_reference
                  ? {
                      'allow-unsigned': client.request_object.by_reference.allow_unsigned_for,
                      'allowed-request-url': client.request_object.by_reference.allowed_request_urls,
                      'http-client': client.request_object.by_reference.http_client_id || undefined,
                    }
                  : undefined,
              }
            : undefined,
          'user-consent': client.user_authentication?.consent
            ? {
                'allow-deselection': client.user_authentication.consent.allow_deselection,
                'only-consentors': client.user_authentication.consent.only_consentors,
                consentors: { consentor: client.user_authentication.consent.consentors },
              }
            : undefined,
          properties: client.properties
            ? {
                property: Object.keys(client.properties).map(key => ({
                  key,
                  value: client.properties[key],
                })),
              }
            : undefined,
  
          // Fields not supported by a DatabaseClient
          'dynamic-client-registration-template': undefined,
          'jwks-uri': undefined,
        }
      : null;
  }
*/

function moveProperty(object, from, to) {
    const [parent, property, value] = getNestedProperty(object, from);
    if (value) {
        delete parent[property];
        setNestedProperty(object, to, value);
    }
}

function getNestedProperty(object, paths) {
    let parent = object;
    while (paths.length > 1) {
        parent = parent[paths.shift()];
        if (!parent) {
            return [null, null, null];
        }
    }
    return [parent, paths[0], parent[paths[0]]];
}

function setNestedProperty(object, paths, value) {
    let parent = object;
    while (paths.length > 1) {
        const path = paths.shift();
        let child = parent[path];
        if (!child) {
            child = {};
            parent[path] = child;
        }
        parent = child;
    }
    parent[paths.shift()] = value;
}
