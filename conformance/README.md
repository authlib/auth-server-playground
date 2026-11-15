# Conformance bench

This folder runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against the playground built from this repository.
The CI runs it on pushes and pull requests, in the `conformance` job of `.github/workflows/tests.yaml`.
The job does not block a merge yet.

This page is for the maintainers of the playground.
It explains how to run the bench, read its results, and update the suite version and the expected results.
It assumes Docker with Compose, [uv](https://docs.astral.sh/uv/), and basic knowledge of OpenID Connect.
It does not explain the test modules: see the [suite documentation](https://gitlab.com/openid/conformance-suite/-/wikis/home).

## Run the bench

Run the script from the root of the repository:

```bash
conformance/run.sh
```

The script does these steps:

1. Download the suite runner, `run-test-plan.py` and its two modules, into `conformance/.cache/`.
2. Build the playground image from the `Dockerfile`, and start the suite, its database, its nginx proxy, the playground and Caddy.
3. Wait for the suite.
4. Run the Config plan, and the Basic plan with discovery and static clients.
5. Compare the results with `expected-failures.json` and `expected-skips.json`.
6. Stop and remove the containers.

The script refuses to start when the containers of a previous run still exist, for example after `--keep`.
It prints the command that stops them.

The script exits with 0 only when the results match the expected files.
A failure or a warning that is not in `expected-failures.json` fails the run.
An entry of `expected-failures.json` that no longer happens also fails the run.
With the images in the Docker cache, a run takes one to three minutes.
The first run also pulls about 1.5 GB of suite images and builds the playground image.

The suite publishes ports 8443 and 8444 on `127.0.0.1`.
The playground port is not published: only the suite reaches it, at `https://playground`.

## TLS in front of the playground

The suite requires HTTPS URLs from the server under test.
Caddy serves the playground over HTTPS, as `Caddyfile` sets:

- The `caddy` service has the network name `playground`, and forwards the requests to the `app` service, the playground.
- The certificate comes from the internal CA of Caddy.
  The CA stays in the `caddy` container, and nothing installs it in a trust store.
- The suite accepts any certificate, so no trust setup is needed, on the host or in the suite.
- The playground runs with `PROXY_FIX=true`, so its issuer and endpoint URLs start with `https://playground`.

## Read the results

The script prints one line for each test module, then the unexpected results.
For each unexpected result, it prints a template entry for `expected-failures.json`.

The script also exports the result of each plan to a zip file in `conformance/results/`.
Each run removes the previous files.
When the run fails, the script also saves the logs of the playground, Caddy and the suite to `conformance/results/compose.log`.
In the CI, the job keeps this folder as the `conformance-results` artifact when it fails.

To read the logs in the suite interface, keep the containers after the run:

```bash
conformance/run.sh --keep
```

Open `https://localhost.emobix.co.uk:8443/`, and accept its self-signed certificate.
The script prints the `plan-detail.html` and `log-detail.html` links of each plan and module.
Stop the containers when done:

```bash
docker compose -f conformance/compose.yaml down --volumes
```

Some modules need a screenshot that a person reviews for a certification.
The browser commands of `config.json` capture the page, and these modules end with `REVIEW`.
The runner counts `REVIEW` as passed.

## Update the suite version

The suite tag is the default value of `SUITE_TAG` in `compose.yaml`, in the image of the `server` and `nginx` services.
`run.sh` downloads the runner files of the same tag.
To try another tag without editing the file, set `SUITE_TAG` in the environment of `run.sh`.

1. List the tags of the suite images:

   ```bash
   curl -s "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/registry/repositories?tags=true" \
     | python3 -c "import json,re,sys; [print(r['path'], sorted((t['name'] for t in r['tags'] if t['name'].startswith('release-v')), key=lambda n: [int(x) for x in re.findall(r'\d+', n)])[-3:]) for r in json.load(sys.stdin)]"
   ```

2. Pick the newest `release-v*` tag that both `openid/conformance-suite` and `openid/conformance-suite/nginx` have.
3. Set it in the two image names of `compose.yaml`.
4. Compare `compose.yaml` with `docker-compose-prebuilt.yml` of the suite at this tag.
5. Run `conformance/run.sh`, and update the expected files if the new version finds other results.

The script downloads the runner files of a tag once, into `conformance/.cache/<tag>/`.
For a tag that moves, such as `unstable`, remove this folder to get the new files.
The runner files of an older tag also stay in `conformance/.cache/`.
Remove the folder to free the space.

## Update the expected results

`expected-failures.json` lists the known failures and warnings, in the format of the suite runner.
Each entry gives the test module, its variant, the block, the condition and the expected result.
Its `comment` says why the result happens.
It only lists Authlib gaps and limits of the bench.
A failure that comes from the playground gets a fix, not an entry.

When an Authlib release fixes a finding:

1. Update Authlib in `uv.lock`.
2. Run `conformance/run.sh`.
   The runner reports each fixed entry as `Expected failure did not happen` or `Expected warning did not happen`.
3. Remove these entries from `expected-failures.json`.
4. Run `conformance/run.sh` again. It exits with 0.

To add an entry, copy the template that the script prints, and replace its `comment`.

`expected-skips.json` lists the modules that the suite is expected to skip, in the same format.

## Test values

`snapshot.json` is the state of the playground under test.
It holds the configuration, one persona, the three clients of `config.json`, and a signing key.
The client secrets and the private key are public test values.
Never use them outside this bench.
