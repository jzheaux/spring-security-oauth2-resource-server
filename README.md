Spring Security OAuth2 Resource Server
=============

Here is a pretty rough draft for what could be Spring 5.1's Resource Server. To run, you can do one of a few things:

Run the Application
-------------------

For the moment, running is a two step process:

1. Build the project

```
./mvnw clean install
```

2. Run the sample:

```
cd samples/boot/oauth2
../../../mvnw spring-boot:run
```

Which will stand up the same messaging service as before, now with JWT-based token security
on the endpoints.

Calls like this should work:

```
curl -H \
  "Authorization: Bearer eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2UucmVhZCIsImlzcyI6InJvYiIsImV4cCI6MjE0NzQwNzIwMCwiaWF0IjoxNTE2MjU1MjAwfQ.XJ8d6fQpo53eH_8nduS7rZOB9szHkVTYkZgzfpF3s6dq0DH-ovgFWBE1evfIXHTQwpAil1X856lp_mvJH0pWVXjM2jM5g_qMGen25210-9R9A94ShiM3iSeMAozHl2L6nmdifJR9Na0fWPo4rogB6_N0GoBG2haaB9yU2r925hw" \
  localhost:8080/messages/1
```

```
curl -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2Uud3JpdGUiLCJpc3MiOiJyb2IiLCJleHAiOjIxNDc0MDcyMDAsImlhdCI6MTUxNjI1NTIwMH0.gehhZAkelPIijBDq0Ds-Pf69h958CzGClyRAYExI-xoXgjAGYllP3E-m6Zjces0tSRDKmSOUZlYW7Kb3zjI85G3xLwVRbKa0VJQyMUPy3ZenhAfPKg6DIAhTms8Qyw3vMS9IlrNMZpLf64sFJFWZXOnTrYblvo3dPwB7J8jy2hg" \
  localhost:8080/messages \
  -d '{ "text" : "Ora Viva!" }'
```

You can take the JWTs from message-both, message-read, and message-write.

Or you can generate your own JWTs, which I did by pasting the contents of id_rsa_pkcs8.pub and id_rsa_pkcs8
in the respective slots on https://jwt.io on their RS256 screen.

id_rsa_pkcs8.pub and id_rsa_pkcs8 are simply the pkcs8 versions of the two provided keys, id_rsa.pub and
id_rsa respectively. I am able to get either to work with the app, but jwt.io needed them in pkcs8
format for some reason.

Run the Tests
-------------

You can do:

```
./mvnw test
```
