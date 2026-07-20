# Gemini CLI adapter smoke test

`run.mjs` invokes the packaged extension hook against a temporary repository
and verifies structured allow/deny decisions for direct file, environment, and
network inputs. It does not establish sandbox conformance or exercise a model.

Run it after building:

```sh
node testbed/gemini/run.mjs
```
