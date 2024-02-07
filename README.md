# Overview

This is a TA designed to retrieve stats from a Rapid7 InsightIDR by using APIs only accessible through their web application.

The TA emulates the web app by using several different REST APIs and GraphQL queries with a variety of headers and cookies.

## To do

- Test handling partner vs. customer environment

## Implemented Queries

| Data | URL | Notes |
|---|---|---|
|All assets/agents | `https://au.query.datacollection.insight.rapid7.com/v1/guardian/graphql` | General graphql endpoint for many queries, though we're currently just using it for this one|
|Basic Detection Rules | `https://au.rest.logs.insight.rapid7.com/management/tags` | Needs x-orgproduct-token header, which we can get from the response to `https://insight.rapid7.com/api/1/user/customers` |
|Users and their statuses/roles| `https://insight.rapid7.com/api/2/user/all/productAccess` | Needs two requests with a delay, the first responds with 202 ("I'm working on it")|
|Event Source Health| `https://au.razor.insight.rapid7.com/api/3/eventsources?index=2&size=20&name=` | Note the params - we have to page through results|
|Log ingestion usage| `https://au.rest.logs.insight.rapid7.com/usage/organizations?from=2023-02-01&to=2024-02-15`| Note the params. Like the web UI we're querying from the 1st of the month 12 months ago to today|

## OTP

When registering the service account for MFA:
1. Choose Google auth on iPhone
2. Take as screenshot of the QR code
3. Quickly, translate it into text using something like https://scanqr.org/
4. Take the secret=BLAH bit and use that with pyotp to generate an OTP
5. Give that OTP to Rapid7 to complete registration
6. Store that secret safely

Working code for pyotp to generate MFA tokens, having installed pyotp (into a venv, during dev) using `pip install pyotp`:

```python
import pyotp
import time

totp = pyotp.TOTP('YOUR_SECRET_HERE')
print(totp.now())
```
