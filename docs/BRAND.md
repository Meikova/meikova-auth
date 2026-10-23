# Meikova Auth branding

The Auth portal uses its own Identity Gateway logo in ice blue (#A6C5FF). Shield belongs to Sentinel Threat Intelligence.

Local assets are self-contained in static/: logo.svg, favicon.svg, favicon.ico, PNG favicons, Apple touch, PWA icons and site.webmanifest. The SSO header embeds the same vector geometry. brand-identity.json records brand metadata and SHA-256 checksums for these images.

Run the offline integration checks from this repository:

```powershell
python -m unittest discover -s tests -p test_brand_assets.py -v
```

These tests do not import server.py or access credentials, signing keys or the database.

Administrative source: the parent Meikova workspace maintains assets/logos/products/meikova-auth/ and scripts/deploy_auth_brand.py. These are not runtime dependencies. The PWA starts at /login; assets use /static/ URLs with an auth-v8 cache version. Deploy the updated static directory alongside the application.
