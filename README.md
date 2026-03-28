# TestSASLConnection
A Java program to test SASL/LDAP connection.

# README.md
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
A minimal Java utility for testing SASL/LDAP connections over SSL. Two standalone source files with no external dependencies beyond the standard JDK.

## Build & Run

No build system — compile manually:

```bash
# Compile
javac BlindSSLSocketFactory.java TestSASLConnection.java

# Run
java TestSASLConnection <userdn> <password> <provider_url>
# Example:
java TestSASLConnection "uid=user,ou=people,dc=example,dc=com" "mypassword" "ldap://ldap.example.com:389"
```

No test framework or linting tools are configured.

## Architecture

Two classes:

- **`TestSASLConnection`** — entry point; authenticates against an LDAP server via JNDI using SASL/SSL, with connection pooling (5–50 connections), and reports timing metrics.
- **`BlindSSLSocketFactory`** — custom `javax.net.SocketFactory` that bypasses certificate validation (trust-all). It is injected into the JNDI context via the `java.naming.ldap.factory.socket` property.

**Security note:** `BlindSSLSocketFactory` disables TLS certificate validation. It exists for testing against self-signed or otherwise untrusted certs and should not be used in production.
