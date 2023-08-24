
import type {CodegenConfig} from '@graphql-codegen/cli';

const config: CodegenConfig = {
  overwrite: true,
  schema: "schema.graphql",
  generates: {
    "databaseClient.ts": {
      plugins: ["typescript"]
    }
  }
};

export default config;
