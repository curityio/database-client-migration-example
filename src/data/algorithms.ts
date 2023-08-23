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

export const ContentEncryptionAlgorithm = {
    A128CBC_HS256: 'A128CBC_HS256',
    A128GCM: 'A128GCM',
    A192CBC_HS384: 'A192CBC_HS384',
    A192GCM: 'A192GCM',
    A256CBC_HS512: 'A256CBC_HS512',
    A256GCM: 'A256GCM',
  } as const;
  
  export const AsymmetricKeyManagementAlgorithm = {
    ECDH_ES: 'ECDH_ES',
    ECDH_ES_A128KW: 'ECDH_ES_A128KW',
    ECDH_ES_A192KW: 'ECDH_ES_A192KW',
    ECDH_ES_A256KW: 'ECDH_ES_A256KW',
    RSA1_5: 'RSA1_5',
    RSA_OAEP: 'RSA_OAEP',
    RSA_OAEP_256: 'RSA_OAEP_256',
  } as const;
  
  export type ObjectValues<T> = T[keyof T];
  export type ContentEncryptionAlgorithmType = ObjectValues<typeof ContentEncryptionAlgorithm>;
  export type AsymmetricKeyManagementAlgorithmType = ObjectValues<typeof AsymmetricKeyManagementAlgorithm>;