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

export async function getResponseErrorMessage(response) {

    if (response.headers['content-type']?.toLowerCase() !== 'application/json') {
        
        const payload = await response.json();

        let text = '';
        if (payload.error_code) {
            text += payload.error_code;
        }
        if (payload.error_description) {
            text += `, ${payload.error_description}`;
        }
        if (payload.errors) {
            for (const error of payload.errors) {
                text += `, ${error}`;
            }
        }

        return text;
    }

    return '';
}

export async function getGraphqlErrorMessage(responseData) {

    let text = '';
    for (const error of responseData.errors) {
        text += `, ${error.message}`;
    }

    return text;
}
