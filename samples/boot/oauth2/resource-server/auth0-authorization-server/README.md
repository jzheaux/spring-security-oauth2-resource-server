Integrating with Auth0
=====================

This sample shows how to integrate an OAuth 2.0 Resource Server with an Auth0 Authorization Server using Spring Security.

Usage
-----

To use, you will need an access token, which you can obtain from your Auth0 instance or from the demo instance:

```bash
https://spring-security-oauth2-demo.auth0.com
```

1. Login to your Auth0 instance and add an API, giving it the identifer "resource-server"
2. Find the corresponding Application and update its Token Endpoint Authentication Mode to BASIC
3. Also, update its Grant Types in the "Advanced Settings" subsection to include "Client Credentials"
4. Note the client id and client credentials
5. Run the following curl command:

```bash
curl -X POST \
  --user {client id}:{client credentials} \
  https://{your-instance}.auth0.com/oauth/token \
  -d "grant_type=client_credentials&audience=resource-server"
```

As an example, here is a curl that I might do against an imaginary Okta instance:

```bash
curl -X POST \
  --user uTITxojBopNxQI1N6QcD6oYjJduugjd0:0jc2TcBAiexUIEblb44WEkwGf3KTgNGMlVGmzRb4FSooaOLTYj6gmbhLQ0yFgwOS \
  https://spring-security-oauth2-demo.auth0.com/oauth/token \
  -d "grant_type=client_credentials&audience=resource-server"
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

