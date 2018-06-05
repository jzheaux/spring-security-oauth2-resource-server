Integrating with Auth0
=====================

This sample shows how to integrate an OAuth 2.0 Resource Server with an Auth0 Authorization Server using Spring Security.

Usage
-----

To use, you will need an access token, which you can obtain from your own connect2id instance or from the demo instance:

```bash
https://demo.c2id.com
```

1. Follow 
(https://connect2id.com/products/server/docs/guides/client-registration#example-client-credentials-grant)[these instructions]
to create your client id and secret with scope "data:read data:write"

2. Run the following curl command:

```bash
curl -X POST \
  --user {client id}:{client credentials} \
  https://{your-instance}/c2id/token \
  -d "grant_type=client_credentials&scope=data:read data:write"
```

As an example, here is a curl that I might do against an imaginary Okta instance:

```bash
curl -X POST \
  --user a23tivqnyq7na:g5tFjoexIUlylwbu_iX7CHwuL072Bjdp7WH9Kmhif5Q \
  https://demo.c2id.com/c2id/token \
  -d "grant_type=client_credentials&scope=data:read data:write"
```

This will result in a response that looks something like this:

```json
{"access_token":"base64-encoded-jwt-token", "token_type":"Bearer", "expires_in":3600}
```

Note the access token.

4. Run the following curl command against this sample:

```bash
curl -H "Authorization: Bearer {base64-encoded-jwt-token}" \
  localhost:8080/hello && echo
```

This will result in a response that contains the value of "sub" from the token.

