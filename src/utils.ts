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
