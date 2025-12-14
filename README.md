# entitlement-jail

>minimal macOS app whose only job is to run a subprocess inside the **App Sandbox**.

The app itself is signed with a Developer ID and opts into the App Sandbox via the `com.apple.security.app-sandbox` entitlement. Any command it launches runs as a child process and **inherits the same sandbox restrictions**.

## What it does

* Runs a single command as a child process
* The child process inherits App Sandbox restrictions from the parent
* No additional entitlements are granted

## What it is

* A small `.app` bundle
* Developer ID signed
* Notarized and Gatekeeper-accepted
* Uses standard process execution (`exec` / spawn)

## Usage

```bash
./EntitlementJail.app/Contents/MacOS/entitlement-jail <command> [args...]
```

Example:

```bash
./EntitlementJail.app/Contents/MacOS/entitlement-jail /bin/ls /
```

## Build

The repository contains a build script that assembles and signs the app bundle:

```bash
IDENTITY="Developer ID Application: Your Name (TEAMID)" ./build-macos.sh
```

The resulting app can be notarized and distributed as a normal macOS application.
