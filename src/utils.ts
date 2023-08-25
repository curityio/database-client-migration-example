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

import {GraphQLError} from "@urql/core/dist/urql-core-chunk";

export async function getHttpErrorAsText(response: any): Promise<string> {

    if (response.headers['content-type']?.toLowerCase() !== 'application/json') {
        
        const payload = await response.json();

        let text = '';
        if (payload.error) {
            text += payload.error;
        }
        if (payload.error_description) {
            text += `, ${payload.error_description}`;
        }

        return text;
    }

    return '';
}

export function getGraphqlErrorAsText(errors: GraphQLError[]): string {

    let text = '';
    for (const error of errors) {
        text += `, ${error.message}`;
    }

    return text;
}
