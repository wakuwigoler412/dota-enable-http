# dota-enable-http

Enables server-side VScript `CreateHTTPRequest` for every custom game in a
running Dota 2. Normally `server.dll` allows it only for five Workshop games.

## Download

Grab `dota-enable-http.exe` from the [latest release](../../releases/latest).

## Usage

Open Dota Workshop Tools, host a map, then run:

```
dota-enable-http
```

| Option | Effect |
|--------|--------|
| `--dry-run` | Find the gates, change nothing. |
| `--pid <pid>` | Target one `dota2.exe` when several run. |
| `--version` | Print the version. |
| `--headless` | No prompts or pause. With several `dota2.exe` and no `--pid`, print their pids and exit. |

Exit codes: `0` success, `1` error, `2` bad arguments, `3` several `dota2.exe`
and no `--pid` (headless only).

## Build

Visual Studio 2022 or later (MSVC, CMake, Ninja), from a Developer prompt:

```
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Output: `build/dota-enable-http.exe`. Local builds report version
`0.0.0-dev`; pass `-DAPP_VERSION=1.2.3` to the configure step to set one.

## Releasing

Versions follow [SemVer](https://semver.org). Tag and push:

```
git tag v1.2.3
git push origin v1.2.3
```

CI builds, tests, and publishes a GitHub release with the exe. A tag with a
suffix (`v1.2.3-rc.1`) is published as a pre-release.
