# Publishing compatible public and private releases

The public repository is [thehappieco/wappie](https://github.com/thehappieco/wappie).
The app, console, billing and hosted operational runbooks belong to the private
`thehappieco/wappie-cloud` repository.

## Public source

Prepare each update on top of the public repository's current branch. Keep its
existing commit history; do not import the history of a private development
checkout or replace the public branch with an unrelated history.

`make public-source` exports only the server, public clients, documentation and
site. The exporter rejects private UI source and runtime configuration and
excludes dependencies, generated builds, local evidence and hosted test runbooks.
Inspect the resulting file list and scan both the new source and Git history for
secrets before publishing. CI verifies that the extracted public source compiles
without the private checkout.

The latest tree no longer contains the private app. Older published versions
remain available in repository history with their original license notices.

## Matching private revision

Publish the validated public revision first. Set `env.WAPPIE_CORE_REF` in the
private `.github/workflows/ci.yml` to its full commit SHA before publishing the matching private
revision. The private pipeline checks out that core at `core/` and the private
repository at `core/commercial/`, preserving its local module and SDK paths.
Do not rely on a moving branch name for a reproducible release.

Record both commit SHAs with the artifact manifest and deployment record. Keep
previous compatible artifacts and database/object backups for rollback; check
migration compatibility before changing a running executable. Runtime deploys
are separate from source publication.
