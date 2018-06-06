Integrating with Okta
=====================

This sample shows how to integrate an OAuth 2.0 Resource Server with an Okta Authorization Server using Spring Security.

Usage
-----

To use, you will need an access token, which you can obtain from your Okta instance.

1. Login to your Okta instance and add a Service-to-Service application
2. Note the client id and client credentials
3. Run the following curl command:

```bash
curl -X POST \
  --user {client id}:{client credentials} \
  https://{your-instance}.oktapreview.com/oauth2/default/v1/token \
  -d "grant_type=client_credentials"
```

As an example, here is a curl that I might do against an Okta instance:

```bash
curl -X POST \
  --user 0oaf5u5g4m6CW4x6z0h7:HR7edRoo3glhF06HTxonOKZvO4I2BWYcC_ocOHlv \
  https://dev-805262.oktapreview.com/oauth2/default/v1/token \
  -d "grant_type=client_credentials"
```

This will result in a response that looks something like this:

```json
{"access_token":"base64-encoded-jwt-token", "token_type":"Bearer", "expires_in":3600}
```

Note the access token.

4. Run the following curl command against this sample:

```bash
curl -H "Authorization: Bearer {base64-encoded-jwt-token}" \
  localhost:8080/hello
```

This will result in a response that contains the value of "sub" from the token.
