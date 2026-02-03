Menu

## Device Nodes

Relevant source files
- [.npmrc](https://github.com/openclaw/openclaw/blob/bf6ec64f/.npmrc)
- [AGENTS.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/AGENTS.md)
- [CHANGELOG.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/CHANGELOG.md)
- [README.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md)
- [apps/android/app/build.gradle.kts](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts)
- [apps/ios/Sources/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist)
- [apps/ios/Tests/Info.plist](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Tests/Info.plist)
- [apps/ios/project.yml](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/project.yml)
- [assets/avatar-placeholder.svg](https://github.com/openclaw/openclaw/blob/bf6ec64f/assets/avatar-placeholder.svg)
- [docs/platforms/fly.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/fly.md)
- [docs/platforms/mac/release.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/platforms/mac/release.md)
- [docs/reference/RELEASING.md](https://github.com/openclaw/openclaw/blob/bf6ec64f/docs/reference/RELEASING.md)
- [extensions/memory-core/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/extensions/memory-core/package.json)
- [fly.private.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.private.toml)
- [fly.toml](https://github.com/openclaw/openclaw/blob/bf6ec64f/fly.toml)
- [package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json)
- [pnpm-lock.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-lock.yaml)
- [pnpm-workspace.yaml](https://github.com/openclaw/openclaw/blob/bf6ec64f/pnpm-workspace.yaml)
- [scripts/clawtributors-map.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/clawtributors-map.json)
- [scripts/update-clawtributors.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.ts)
- [scripts/update-clawtributors.types.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/update-clawtributors.types.ts)
- [scripts/write-build-info.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/scripts/write-build-info.ts)
- [src/agents/pi-embedded-runner-extraparams.live.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.live.test.ts)
- [src/agents/pi-embedded-runner-extraparams.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/agents/pi-embedded-runner-extraparams.test.ts)
- [src/cli/nodes-cli.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-cli.ts)
- [src/cli/nodes-screen.test.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.test.ts)
- [src/cli/nodes-screen.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.ts)
- [src/cli/program.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/program.ts)
- [src/index.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/index.ts)
- [src/infra/git-commit.ts](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/infra/git-commit.ts)
- [ui/package.json](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/package.json)
- [ui/src/styles.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles.css)
- [ui/src/styles/layout.mobile.css](https://github.com/openclaw/openclaw/blob/bf6ec64f/ui/src/styles/layout.mobile.css)

Device nodes are companion applications (iOS, Android, macOS) that pair with the OpenClaw Gateway to provide device-local capabilities. They enable a gateway running on one machine (e.g., a Linux VPS) to invoke actions on other devices (e.g., take a photo on your iPhone, run a command on your Mac).

This page covers the node architecture, protocol, and platform support. For pairing and discovery details, see [Node Pairing and Discovery](https://deepwiki.com/openclaw/openclaw/11.1-node-pairing-and-discovery). For the specific capabilities each platform provides, see [Node Capabilities](https://deepwiki.com/openclaw/openclaw/11.2-node-capabilities).

---

## Node Architecture

Device nodes solve the separation-of-execution problem: the gateway handles agent logic, channels, and tool orchestration, but some tools need to run on specific devices (camera access, TCC-gated system commands, location services).

The architecture splits execution into two domains:

| Execution Domain | Description | Examples |
| --- | --- | --- |
| **Gateway Host** | Where the gateway process runs | `exec` tool (default), channel connections, agent runtime |
| **Node Host** | Device-local actions via paired nodes | `camera.snap`, `screen.record`, `location.get`, `system.run` (macOS) |

```
macOS NodeAndroid NodeiOS NodeNode DiscoveryGateway Host (Linux VPS)AdvertisesDiscoversDiscoversDiscoversnode.invoke RPCnode.invoke RPCnode.invoke RPCGateway Process
Port 18789Agent Runtime
Tool Registryexec Tool
Default HostBonjour/DNS-SD
_openclaw-gw._tcpPairing Flow
Token AuthiOS App
ai.openclaw.iosCapabilities
camera, location,
screen.recordAndroid App
ai.openclaw.androidCapabilities
camera, screen.recordmacOS App
Node ModeCapabilities
camera, system.run,
canvas, location
```

**Sources:**

- [README.md 143-147](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L143-L147)
- [README.md 214-221](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L214-L221)

---

## The node.invoke Protocol

Tools that require device-local execution use the `node.invoke` RPC method. The gateway protocol includes node management primitives:

| RPC Method | Purpose | Example |
| --- | --- | --- |
| `node.list` | Enumerate paired nodes | CLI: `openclaw nodes list` |
| `node.describe` | Get capabilities + permissions | Show TCC status, available actions |
| `node.invoke` | Execute capability on node | `camera.snap`, `screen.record`, `location.get` |

When the agent runtime encounters a tool that targets a node (e.g., `camera.snap`), it:

1. Resolves which node to target (by node ID, or defaults to first capable node)
2. Sends `node.invoke` RPC with capability name and parameters
3. Node validates permissions (e.g., camera access granted)
4. Node executes action and returns payload (base64 image, location coordinates, etc.)
5. Runtime injects result into agent context
```
Device OSiOS/Android NodeGateway CoreAgent RuntimeDevice OSiOS/Android NodeGateway CoreAgent Runtimealt[Permission Denied][Permission Granted]Tool call: camera.snapResolve node target(first capable)node.invoke RPC{capability: "camera.snap", params: {...}}Check camera permissionTCC DeniedError: PERMISSION_MISSINGTool errorPermission OKCapture photoImage dataSuccess: {format: "jpeg", base64: "..."}Tool resultInject image into context
```

**Sources:**

- [README.md 222-229](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L222-L229)
- [src/cli/nodes-screen.ts 1-51](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.ts#L1-L51)

---

## Platform Support

OpenClaw provides three node implementations:

### iOS Node

**Bundle ID:**`ai.openclaw.ios`  
**Discovery:** Bonjour (NSBonjourServices)  
**Build System:** Xcode + xcodegen

The iOS app pairs with the gateway over the local network or Tailscale. It advertises its presence and waits for pairing approval.

**Key Info.plist Entries:**

| Key | Value | Purpose |
| --- | --- | --- |
| `NSBonjourServices` | `_openclaw-gw._tcp` | Discover gateway |
| `NSCameraUsageDescription` | Permission prompt text | Camera access |
| `NSLocationWhenInUseUsageDescription` | Permission prompt text | Location access |
| `NSMicrophoneUsageDescription` | Permission prompt text | Voice wake |

**Sources:**

- [apps/ios/Sources/Info.plist 30-42](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist#L30-L42)
- [apps/ios/project.yml 1-135](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/project.yml#L1-L135)

### Android Node

**Package Name:**`ai.openclaw.android`  
**Discovery:** DNS-SD (dnsjava library)  
**Build System:** Gradle (Kotlin)

The Android app uses `dnsjava` for wide-area Bonjour (DNS-SD unicast queries) to support Tailscale discovery domains.

**Key Dependencies:**

| Dependency | Purpose |
| --- | --- |
| `dnsjava:3.6.4` | DNS-SD for node discovery |
| `androidx.camera:camera-*` | Camera capture (CameraX) |
| `androidx.exifinterface` | Image metadata |
| `okhttp3:5.3.2` | WebSocket transport |

**Sources:**

- [apps/android/app/build.gradle.kts 1-129](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L1-L129)
- [apps/android/app/build.gradle.kts 115-116](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L115-L116)

### macOS Node Mode

The macOS app can run as a node (in addition to hosting the gateway). This allows a remote gateway to invoke macOS-specific capabilities.

**Capabilities unique to macOS:**

- `system.run`: Execute shell commands with TCC permission checks
- `system.notify`: Post user notifications
- `canvas.*`: A2UI rendering and interaction

**Note:** The macOS app typically runs the gateway locally, but can be configured to act as a node for a remote gateway.

**Sources:**

- [README.md 147-148](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L147-L148)
- [README.md 222-236](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L222-L236)

---

## Node CLI

The CLI provides node management commands:

```
# List paired nodes
openclaw nodes list

# Show node capabilities and permissions
openclaw nodes describe <node-id>

# Execute a capability directly (testing)
openclaw nodes invoke <node-id> camera.snap --format jpeg
```

**CLI Implementation:**

- [src/cli/nodes-cli.ts 1-2](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-cli.ts#L1-L2)

**Screen Recording Utilities:**

- [src/cli/nodes-screen.ts 1-51](https://github.com/openclaw/openclaw/blob/bf6ec64f/src/cli/nodes-screen.ts#L1-L51) - Payload parsing, temp file handling

---

## Configuration

Nodes do not require gateway configuration to pair. Once paired, they are automatically available to tools.

**Agent Configuration:**

To restrict which agent can invoke node capabilities, configure tool policies. By default, all agents can use `node.invoke` if the tool is enabled.

**Example: Restrict node tools to main agent**

```
{
  "agents": {
    "defaults": {
      "tools": {
        "allow": ["exec", "read", "write"],
        "deny": ["nodes"]
      }
    },
    "list": [
      {
        "id": "main",
        "default": true,
        "tools": {
          "allow": ["nodes"]
        }
      }
    ]
  }
}
```

---

## Discovery and Pairing

Nodes discover the gateway via Bonjour/DNS-SD:

1. Gateway advertises `_openclaw-gw._tcp` on the local network (or Tailscale)
2. Node apps scan for the service
3. User approves pairing in gateway (CLI or Control UI)
4. Node receives pairing token
5. Node connects via WebSocket with token auth

For full pairing details, see [Node Pairing and Discovery](https://deepwiki.com/openclaw/openclaw/11.1-node-pairing-and-discovery).

**Sources:**

- [apps/ios/Sources/Info.plist 30-33](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist#L30-L33)
- [apps/android/app/build.gradle.kts 115-116](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L115-L116)

---

## Node vs Gateway Execution

The execution model is straightforward:

| Tool / Capability | Default Execution | Override |
| --- | --- | --- |
| `exec` | Gateway host | Via `--node <id>` or `/exec` directive |
| `read`, `write`, `edit` | Gateway host | N/A |
| `browser` | Gateway host | Can proxy via node if configured |
| `camera.*` | Node host | Auto-routed to capable node |
| `screen.record` | Node host | Auto-routed to capable node |
| `location.get` | Node host | Auto-routed to capable node |
| `system.run` (macOS) | Node host (requires TCC) | macOS-only capability |

**Example: Remote gateway, local Mac node**

```
Gateway (Linux VPS) ────> exec tool runs here
                     └───> node.invoke: system.run
                            └──> macOS Node: executes with local TCC permissions
```

**Sources:**

- [README.md 214-221](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L214-L221)

---

## Build and Versioning

Node apps follow the main OpenClaw version scheme. Version numbers must stay synchronized for protocol compatibility.

**Version Locations:**

| Platform | File | Key |
| --- | --- | --- |
| iOS | [apps/ios/Sources/Info.plist 21-24](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist#L21-L24) | `CFBundleShortVersionString`, `CFBundleVersion` |
| Android | [apps/android/app/build.gradle.kts 24-25](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L24-L25) | `versionName`, `versionCode` |

**Build Commands:**

```
# iOS (requires Xcode)
pnpm ios:gen    # Generate .xcodeproj
pnpm ios:build  # Build for simulator
pnpm ios:run    # Build + launch in simulator

# Android
pnpm android:assemble  # Build APK
pnpm android:install   # Install to connected device
pnpm android:run       # Install + launch
```

**Sources:**

- [package.json 103-110](https://github.com/openclaw/openclaw/blob/bf6ec64f/package.json#L103-L110)
- [apps/ios/Sources/Info.plist 21-24](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/ios/Sources/Info.plist#L21-L24)
- [apps/android/app/build.gradle.kts 24-25](https://github.com/openclaw/openclaw/blob/bf6ec64f/apps/android/app/build.gradle.kts#L24-L25)

---

## Summary

Device nodes extend the OpenClaw Gateway's reach to local device capabilities. They:

- Pair via Bonjour/DNS-SD discovery
- Authenticate with gateway-issued tokens
- Advertise capabilities (camera, screen, location, system commands)
- Execute actions via `node.invoke` RPC
- Return results to the agent runtime

This architecture allows a single gateway (running anywhere) to orchestrate device-local actions across multiple platforms, bridging cloud/VPS execution with mobile/desktop device affordances.

**Sources:**

- [README.md 143-148](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L143-L148)
- [README.md 214-221](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L214-L221)
- [README.md 222-236](https://github.com/openclaw/openclaw/blob/bf6ec64f/README.md#L222-L236)

<svg id="mermaid-fu8dstus3vp" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-7khuxtjp8f" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg> <svg id="mermaid-5cnv3xfsc84" width="100%" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 2412 512" style="max-width: 512px;" role="graphics-document document" aria-roledescription="error"><g></g><g><path class="error-icon" d="m411.313,123.313c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32-9.375,9.375-20.688-20.688c-12.484-12.5-32.766-12.5-45.25,0l-16,16c-1.261,1.261-2.304,2.648-3.31,4.051-21.739-8.561-45.324-13.426-70.065-13.426-105.867,0-192,86.133-192,192s86.133,192 192,192 192-86.133 192-192c0-24.741-4.864-48.327-13.426-70.065 1.402-1.007 2.79-2.049 4.051-3.31l16-16c12.5-12.492 12.5-32.758 0-45.25l-20.688-20.688 9.375-9.375 32.001-31.999zm-219.313,100.687c-52.938,0-96,43.063-96,96 0,8.836-7.164,16-16,16s-16-7.164-16-16c0-70.578 57.422-128 128-128 8.836,0 16,7.164 16,16s-7.164,16-16,16z"></path><path class="error-icon" d="m459.02,148.98c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l16,16c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16.001-16z"></path><path class="error-icon" d="m340.395,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688 6.25-6.25 6.25-16.375 0-22.625l-16-16c-6.25-6.25-16.375-6.25-22.625,0s-6.25,16.375 0,22.625l15.999,16z"></path><path class="error-icon" d="m400,64c8.844,0 16-7.164 16-16v-32c0-8.836-7.156-16-16-16-8.844,0-16,7.164-16,16v32c0,8.836 7.156,16 16,16z"></path><path class="error-icon" d="m496,96.586h-32c-8.844,0-16,7.164-16,16 0,8.836 7.156,16 16,16h32c8.844,0 16-7.164 16-16 0-8.836-7.156-16-16-16z"></path><path class="error-icon" d="m436.98,75.605c3.125,3.125 7.219,4.688 11.313,4.688 4.094,0 8.188-1.563 11.313-4.688l32-32c6.25-6.25 6.25-16.375 0-22.625s-16.375-6.25-22.625,0l-32,32c-6.251,6.25-6.251,16.375-0.001,22.625z"></path><text class="error-text" x="1440" y="250" font-size="150px" style="text-anchor: middle;">Syntax error in text</text> <text class="error-text" x="1250" y="400" font-size="100px" style="text-anchor: middle;">mermaid version 11.12.2</text></g></svg>