# Entitlement Jail

Run an arbitrary command inside a macOS `.app` that is signed with specific entitlements (by default: App Sandbox). This is useful for quickly testing how a tool behaves when "jailed" by a sandbox/entitlement set.

The app executable is a tiny Rust wrapper in `runner/` that `exec()`s the command you pass, so the child process inherits the app's sandbox/entitlements.

## Requirements

- macOS 14+ (see `LSMinimumSystemVersion` in the app `Info.plist`)
- Rust toolchain (to build `runner/`)
- Xcode Command Line Tools (for `codesign`)

## Build

1. Build the runner:

   ```sh
   cd runner
   cargo build --release
   cd ..
   ```

2. Create an app bundle and copy the binary in:

   ```sh
   APP=EntitlementJail.app
   mkdir -p "$APP/Contents/MacOS"
   cp runner/target/release/runner "$APP/Contents/MacOS/entitlement-jail"
   ```

3. Add an `Info.plist`:

   ```sh
   cat > "$APP/Contents/Info.plist" <<'PLIST'
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>CFBundleExecutable</key><string>entitlement-jail</string>
     <key>CFBundleIdentifier</key><string>com.yourteam.entitlement-jail</string>
     <key>CFBundleName</key><string>EntitlementJail</string>
     <key>CFBundlePackageType</key><string>APPL</string>
     <key>CFBundleShortVersionString</key><string>1.0</string>
     <key>CFBundleVersion</key><string>1</string>
     <key>LSMinimumSystemVersion</key><string>14.0</string>
   </dict>
   </plist>
   PLIST
   ```

4. Sign the app with the entitlements in `EntitlementJail.entitlements` (ad-hoc signing is fine for local testing):

   ```sh
   codesign --force --deep --sign - --entitlements EntitlementJail.entitlements "$APP"
   ```

## Usage

Run the app's executable and pass the command to "jail":

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail /usr/bin/id
./EntitlementJail.app/Contents/MacOS/entitlement-jail /bin/ls "$HOME/Desktop"
```

## Customizing entitlements

Edit `EntitlementJail.entitlements`, then re-run the `codesign ...` step.

For example, to allow outbound network access, add:

```xml
<key>com.apple.security.network.client</key>
<true/>
```
