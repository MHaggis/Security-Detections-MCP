# Supabase production root certificate

`supabase-prod-ca-2021.crt` is a public root CA certificate, not a credential or
private key. The authenticated Supabase project dashboard's **Download
certificate** link provided this source on 2026-11-04:

https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt

Subject/issuer: Supabase Root 2021 CA, Supabase Inc.

SHA-256 fingerprint:
`807025AD50D4ED219D2C9C7D299C004F824EB00CF7F65AFEF607D07B72E6CAFA`

Validity: 2021-04-28 10:56:53 UTC through 2031-04-26 10:56:53 UTC.
The project session-pooler chain and hostname were verified against this CA.

Nightly adds it to Node's trusted roots using NODE_EXTRA_CA_CERTS at process
startup. The pg client still uses rejectUnauthorized=true and verifies the
server hostname. This supplements the trust store; it does not turn off TLS
verification or replace hostname checks.

Before replacing or extending this certificate, obtain the current certificate
from the authenticated provider dashboard, verify its fingerprint/provenance,
validity, CA constraints and actual project pooler chain/hostname, then update
the integration guard and this note together. Run the signed-TLS positive and
untrusted-CA/wrong-hostname negative tests before release. Never resolve an
expiry or trust failure by disabling verification.
