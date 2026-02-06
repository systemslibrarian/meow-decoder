/**
 * MeowScanner — Minimal React Native QR scanner component for the
 * meow-bridge protocol.
 *
 * Captures QR codes from the camera and streams raw bytes to the CLI
 * bridge server.  No crypto runs on the device.
 *
 * Dependencies:
 *   react-native-vision-camera ^4.0.0
 *   react-native-worklets-core ^1.0.0
 *
 * Usage:
 *   <MeowScanner
 *     bridgeUrl="ws://192.168.1.42:9999"
 *     onProgress={(p) => console.log(p.percent)}
 *     onResult={(r) => Alert.alert(r.success ? "Done!" : "Failed")}
 *     onError={(e) => Alert.alert("Error", e.message)}
 *   />
 */

import React, { useCallback, useEffect, useRef, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import {
  Camera,
  useCameraDevice,
  useCameraPermission,
  useCodeScanner,
} from "react-native-vision-camera";

import {
  useBridge,
  type BridgeProgress,
  type BridgeResult,
  type BridgeError,
} from "./useBridge";

// ── Props ────────────────────────────────────────────────────────────────────

export interface MeowScannerProps {
  /** WebSocket URL of the meow-bridge server */
  bridgeUrl: string;
  /** Called on decode progress updates */
  onProgress?: (p: BridgeProgress) => void;
  /** Called when decoding completes */
  onResult?: (r: BridgeResult) => void;
  /** Called on errors */
  onError?: (e: BridgeError) => void;
}

// ── Component ────────────────────────────────────────────────────────────────

export function MeowScanner({
  bridgeUrl,
  onProgress,
  onResult,
  onError,
}: MeowScannerProps) {
  const { hasPermission, requestPermission } = useCameraPermission();
  const device = useCameraDevice("back");
  const { status, connect, sendFrame } = useBridge({
    url: bridgeUrl,
    onProgress,
    onResult,
    onError,
  });

  // Track last sent payload to de-duplicate consecutive identical frames
  const lastPayloadRef = useRef<string>("");
  const [framesScanned, setFramesScanned] = useState(0);

  // Request camera permission on mount
  useEffect(() => {
    if (!hasPermission) {
      requestPermission();
    }
  }, [hasPermission, requestPermission]);

  // Auto-connect to bridge
  useEffect(() => {
    if (hasPermission && status === "disconnected") {
      connect();
    }
  }, [hasPermission, status, connect]);

  // QR code scanner callback
  const codeScanner = useCodeScanner({
    codeTypes: ["qr"],
    onCodeScanned: useCallback(
      (codes) => {
        if (status !== "connected" && status !== "decoding") return;

        for (const code of codes) {
          // react-native-vision-camera returns string value;
          // for binary QR we need the raw bytes.  The library exposes
          // `code.frame?.bytes` on supported platforms, otherwise
          // fall back to encoding the string value.
          let payload: Uint8Array;
          if (code.frame?.bytes) {
            payload = new Uint8Array(code.frame.bytes);
          } else if (code.value) {
            payload = new TextEncoder().encode(code.value);
          } else {
            continue;
          }

          // De-duplicate: skip if identical to last frame
          const payloadKey = uint8ToHex(payload);
          if (payloadKey === lastPayloadRef.current) continue;
          lastPayloadRef.current = payloadKey;

          sendFrame(payload);
          setFramesScanned((n) => n + 1);
        }
      },
      [status, sendFrame]
    ),
  });

  // ── Render ─────────────────────────────────────────────────────────────

  if (!hasPermission) {
    return (
      <View style={styles.container}>
        <Text style={styles.text}>Camera permission required 📷</Text>
      </View>
    );
  }

  if (!device) {
    return (
      <View style={styles.container}>
        <Text style={styles.text}>No camera device found</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Camera
        style={StyleSheet.absoluteFill}
        device={device}
        isActive={true}
        codeScanner={codeScanner}
      />
      <View style={styles.overlay}>
        <Text style={styles.status}>
          {status === "connected"
            ? `🐱 Scanning... (${framesScanned} frames)`
            : status === "decoding"
            ? `🔐 Decoding... (${framesScanned} frames sent)`
            : status === "done"
            ? "✅ Decode complete!"
            : status === "error"
            ? "❌ Error"
            : `⏳ ${status}...`}
        </Text>
      </View>
    </View>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function uint8ToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#000",
    justifyContent: "center",
    alignItems: "center",
  },
  overlay: {
    position: "absolute",
    bottom: 60,
    left: 0,
    right: 0,
    alignItems: "center",
  },
  status: {
    color: "#fff",
    fontSize: 18,
    backgroundColor: "rgba(0,0,0,0.6)",
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 8,
    overflow: "hidden",
  },
  text: {
    color: "#fff",
    fontSize: 16,
  },
});
