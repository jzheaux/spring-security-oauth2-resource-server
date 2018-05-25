Playing with the Sample
=======================

There are several ways that you can play with this sample:

1. The Authorized Way
---------------------

In the src/main/resources directory there is a token that already has the 'ok' scope granted. If you navigate in your
terminal to that directory, e.g.

```bash
cd {location-of-sample}/src/main/resources
```

then you will be able to do:

```bash
curl -H "Authorization: Bearer `cat ok_token`" localhost:8080/ok
```

Or, you can copy-paste the value in directly:

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im9rIiwiZXhwIjozMzA2MzI3MDk1OCwianRpIjoiNmZkMzljMWYtMjE2OS00ODZiLWExMDUtMTBlNmU3NDMwNWM4In0.VKhal1JngnA8lG9CD14ezMUA_p-wr85cVw9jkxUcKtNLjrGcaWPHlAAGfF8TNK7RnikEQllvHOyXy3GoDgdnjcPGxcdPZ5gzSQtJEJUicOkjnsc_SQIq3Sw0Vxua5xkOUgM9_m3-2zjUibhLuMFMnWcdQHGetJx3OGbEU_ku3bBDm41zlEVQ1YcWszCz2jfD3EsrvWf2m_7xqQHwpz8hMF82l4ndAGNqFuQ-hos4JmwWc38HhYR3AsT6PvsiMueBFJh3OcC7KtP9en78Xvz_-q8i5lRH1XAwpLjvQfTSk0tZ68DFPYKk8SVhDf53VGPVVR8Lhoz60ZpsESr31l84ug" localhost:8080/ok
```

2. The *Un*authorized Way
-------------------------

You can also hit the app without a token:

```bash
curl -v localhost:8080/ok
```

And see what happens.

3. The DIY way - Generate Your Own Token
----------------------------------------

You can generate your own token using the accompanying utilities project with the `Signer` application, using the
private key--`simple`--also found in the src/main/resources directory. Once generated, take a look again at section 1

4. The DIY way - Generate Your Own Key Pair
-------------------------------------------

You can generate your own key pair (which you'd then use to generate your own token) using the accompanying utilities
project with the `KeyGen` application.

Place that keypair into the src/main/resources directory and alter the application.yml properties file accordingly.

Once the app is started, follow the instructors for generating your own token.
