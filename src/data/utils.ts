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

export type ObjectValues<T> = T[keyof T];

const SortOrder = {
  ASCENDING: 'ASCENDING',
  DESCENDING: 'DESCENDING',
} as const;

export type SortOrderType = ObjectValues<typeof SortOrder>;
