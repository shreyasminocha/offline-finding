# Offline Finding

## CLI

Make sure to set the environment variables listed in `.env.example`. For the time being, we generate these with [FindMy.py](https://github.com/malmeloo/FindMy.py). Using FindMy.py's `account.json`:

```sh
# APPLE_AUTH_DSID
cat account.json | jq '.login_state.data.mobileme_data.tokens.searchPartyToken'

# APPLE_AUTH_SEARCH_PARTY_TOKEN
cat account.json | jq '.login_state.data.dsid'
```

```sh
# Fetch "raw" (undecrypted) reports
cargo run -- --anisette-server 'http://localhost:8000' fetch-raw-reports (--private-key|--public-key|--hashed-public-key) <ARG>

# Fetch and decrypt reports
cargo run -- --anisette-server 'http://localhost:8000' fetch-reports '[base64-encoded ephemeral private key]'
```

See `cargo run -- --help` for more.
