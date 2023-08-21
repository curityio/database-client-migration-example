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
    moveProperty(client, ['id'], ['client_id']);
    moveProperty(client, ['scope'], ['scopes']);
    moveProperty(client, ['audience'], ['audiences']);
    moveProperty(client, ['secret'], ['client_authentication', 'primary', 'secret']);
    return client;
}

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
