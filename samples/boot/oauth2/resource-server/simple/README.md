Playing with the Sample
=======================

There are several ways that you can play with this sample:

1. The Authorized Way
---------------------

In the src/main/resources directory there is valid bearer token. If you navigate in your
terminal to that directory, e.g.

```bash
cd {location-of-sample}/src/main/resources
```

then you will be able to do:

```bash
curl -H "Authorization: Bearer `cat token`" localhost:8080/authenticated
```

Or, you can copy-paste the value in directly:

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYXJvbGQiLCJleHAiOjMzMDYzMjkwMzg5fQ.DHZOFSUe2xoH0_PWOX8hLo5jPeY2qZposRWPGGwEhBiPfNeUsj85pkmNCtQ3YZ-ENzfGHUYBi9-oCH4oQxrYjYJPs3N939ZQmPrRWeL38tQUx1z6j1kWMezEM59JC4ucnA1kIocxKnQliwHd8o6v-Tn38TdwzOj4YTVBcvBaM50ZmGGo3eShMJrILkLs5vAna6z073y_Qr999UxjdeowZeOl5oB2icsrbye3WYiZB3HGEcsz5M_VUAaqIXJoDrVdersxqsOw64ufXHzTq-Ox6wBrqftSY9h4R1zvsuqVjTxnFpC5JIB9GqI5yfPpVyWG2LG90oLo5W6iGTCMpoiIqQ" localhost:8080/authenticated
```

2. The *Un*authorized Way
-------------------------

You can also hit the app without a token:

```bash
curl -v localhost:8080/authenticated
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
