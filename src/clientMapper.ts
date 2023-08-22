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

/*
 * Initial approach to get a basic working solution and focus on the setup
 */
export function mapStaticClientToDatabaseClient(client: any): any {

    const dataMap: any = {
        'access_token_ttl': client['access-token-ttl'] || undefined,
        'allowed_origins': client['allowed-origins'] || undefined,
        'application_url': client['application-url'] || undefined,
        'audience': client['audiences'] || undefined,
        'claims_mapper_id': client['claims-mapper'] || undefined,
        'capabilities': getCapabilities(client['capabilities']) || undefined,
        'client_id': client['id'] || undefined,
        'redirect_uris': client['redirect-uris'] || undefined,
        'scopes': client['scope'] || [],
        'client_authentication': getClientAuthentication(client['secret']) || undefined,
        'user_authentication': getUserAuthentication(client['user-authentication']) || undefined,
        'validate_port_on_loopback_interfaces': client['validate-port-on-loopback-interfaces'] || undefined,
    }

    Object.keys(dataMap).forEach((key) => dataMap[key] === undefined && delete dataMap[key]);
    return dataMap;
}

function getCapabilities(capabilities: any): any {

    if (capabilities?.code) {
        return {
            code: {
                type: 'CODE',
            },
        };
    }

    if (capabilities?.introspection) {
        return {
            introspection: {
                type: 'INTROSPECTION',
            },
        };
    }

    return undefined;
}

function getClientAuthentication(secret: string) {

    if (secret) {
        return {
            primary: {
                secret: {
                    secret,
                },
            },
        };
    }

    return undefined;
}

function getUserAuthentication(userAuthentication: any): any {

    if (userAuthentication) {
        return {
            context_info: '',
        };
    }

    return undefined;
}

/*
 * TODO: Use a more generic approach, using this data map from the Admin UI
 */
export function mapClientPropertyNameToDatabaseClient(propertyOrPath: string): any {

    const map = {
        'access-token-ttl': 'access_token_ttl',
        'allowed-origins': 'allowed_origins',
        'application-url': 'application_url',
        'asymmetric-key': 'client_authentication=primary=asymmetric_key_id',
        'attestation=android=android-policy': 'capabilities=haapi=client_attestation=policy_id',
        'attestation=android=package-name': 'capabilities=haapi=client_attestation=package_names',
        'attestation=android=signature-digest': 'capabilities=haapi=client_attestation=signature_fingerprints',
        'attestation=attestation-type': 'capabilities=haapi=client_attestation=type',
        'attestation=ios=app-id': 'capabilities=haapi=client_attestation=app_id',
        'attestation=ios=ios-policy': 'capabilities=haapi=client_attestation=policy_id',
        'attestation=web=web-policy': 'capabilities=haapi=client_attestation=policy_id',
        'capabilities=assertion=jwt=trust=asymmetric-signing-key': 'capabilities=assertion=jwt=signing=asymmetric_key_id',
        'capabilities=backchannel-authentication=allowed-authenticators':
            'capabilities=backchannel=allowed_backchannel_authenticators',
        'capabilities=code=require-pushed-authorization-requests': 'capabilities=code=require_pushed_authorization_request',
        'capabilities=code=require-pushed-authorization-requests=allow-per-request-redirect-uris':
            'allow_per_request_redirect_uris',
        'claims-mapper': 'claim_mapper_id',
        'client-authentication-method': 'client_authentication=primary=type',
        'client-name': 'name',
        'credential-manager': 'client_authentication=primary=credential_manager_id',
        'id-token-encryption=content-encryption-algorithm': 'id_token=id_token_encryption=allowed_content_encryption_alg',
        'id-token-encryption=encryption-key': 'id_token=id_token_encryption=encryption_key_id',
        'id-token-encryption=key-management-algorithm': 'id_token=id_token_encryption=allowed_key_management_alg',
        'no-authentication': 'client_authentication=primary=no_authentication',
        'privacy-policy-url': 'policy_uri',
        'proof-key=require-proof-key': 'capabilities=code=proof_key=require_proof_key',
        'redirect-uri-validation-policy': 'redirect_uri_validation_policy_id',
        'redirect-uris': 'redirect_uris',
        'refresh-token-ttl': 'refresh_token=refresh_token_ttl',
        'request-object': 'request_object',
        'request-object=allow-unsigned-for-by-value': 'request_object=allow_unsigned_for_by_value',
        'request-object=by-reference': 'request_object=by_reference',
        'request-object=by-reference=allow-unsigned': 'request_object=by_reference=allow_unsigned_for',
        'request-object=by-reference=allowed-request-url': 'request_object=by_reference=allowed_request_urls',
        'request-object=by-reference=http-client': 'request_object=by_reference=http_client_id',
        'request-object=issuer': 'request_object=request_jwt_issuer',
        'request-object=signature-verification-key': 'request_object=request_jwt_signature_verification_key',
        'require-secured-authorization-response': 'require_secured_authorization_response',
        'signed-userinfo': 'userinfo_signed_issuer_id',
        'symmetric-key': 'client_authentication=primary=symmetric_key',
        'terms-of-service-url': 'tos_uri',
        'use-pairwise-subject-identifiers=sector-identifier': 'sector_identifier',
        'user-authentication=allowed-authenticators': 'user_authentication=allowed_authenticators',
        'user-authentication=allowed-post-logout-redirect-uris': 'user_authentication=allowed_post_logout_redirect_uris',
        'user-authentication=authenticator-filters': 'user_authentication=authenticator_filters',
        'user-authentication=backchannel-logout-uri': 'user_authentication=backchannel_logout_uri',
        'user-authentication=context-info': 'user_authentication=context_info',
        'user-authentication=force-authn': 'user_authentication=force_authentication',
        'user-authentication=freshness': 'user_authentication=freshness',
        'user-authentication=frontchannel-logout-uri': 'user_authentication=frontchannel_logout_uri',
        'user-authentication=http-client': 'user_authentication=http_client_id',
        'user-authentication=locale': 'user_authentication=locale',
        'user-authentication=required-claims': 'user_authentication=required_claims',
        'user-authentication=template-area': 'user_authentication=template_area',
        'user-consent': 'user_authentication=consent',
        'user-consent=allow-deselection': 'user_authentication=consent=allow_deselection',
        'user-consent=consentors=consentor': 'user_authentication=consent=consentors',
        'user-consent=only-consentors': 'user_authentication=consent=only_consentors',
        'validate-port-on-loopback-interfaces': 'validate_port_on_loopback_interfaces',
        audience: 'audiences',
        description: 'description',
        enabled: 'status',
        logo: 'logo_uri',
        scope: 'scopes',
        secret: 'client_authentication=primary=secret',
    };
  
    return (map as any)[propertyOrPath];
}
