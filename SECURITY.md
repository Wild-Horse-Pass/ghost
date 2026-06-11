# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories
(the **Security → Advisories** tab of this repository) or by encrypted email to
the maintainer key below. Do not open public issues for security reports.

## Verifying Releases

Release artifacts are published with a `SHA256SUMS.txt` manifest and a detached
PGP signature `SHA256SUMS.txt.asc` produced by the maintainer release key.

1. Import the release-signing key:

   ```sh
   gpg --keyserver hkps://keys.openpgp.org --recv-keys "777F E81F 8CC0 77FD 3D08  055E 852C 2B31 90F5 B928"
   ```

2. Verify the manifest signature:

   ```sh
   gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
   ```

   Confirm the "Good signature" is from the fingerprint below.

3. Verify a downloaded artifact against the manifest:

   ```sh
   sha256sum --check --ignore-missing SHA256SUMS.txt
   ```

If `SHA256SUMS.txt.asc` is absent from a release, that release was published
unsigned (the signing key was not configured in CI) — treat it with caution.

## Release-Signing Key

| Name | Fingerprint |
|------|-------------|
| defenwycke | `777F E81F 8CC0 77FD 3D08  055E 852C 2B31 90F5 B928` |

(Key id `852C2B3190F5B928`, ed25519.)
