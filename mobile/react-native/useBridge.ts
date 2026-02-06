/**
 * useBridge — React Native hook for WebSocket communication with the
 * meow-bridge CLI server.
 *
 * The phone is a dumb scanner: it sends raw QR bytes over WebSocket and
 * receives progress/result updates.  No crypto runs on the device.
 *
 * See mobile/ARCHITECTURE.md for wire protocol details.
 */

import { useCallback, useEffect, useRef, useState } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

export interface BridgeProgress {
  frames_received: number;
  frames_needed: number;
  blocks_decoded: number;
  blocks_total: number;
  percent: number;
}

export interface BridgeResult {
  success: boolean;
  output_file: string;
  output_size: number;
  elapsed_s: number;
  error: string | null;
}

export interface BridgeError {
  code: string;
  message: string;
}

type BridgeStatus = "disconnected" | "connecting" | "connected" | "decoding" | "done" | "error";

export interface UseBridgeOptions {
  /** WebSocket URL, e.g. ws://192.168.1.42:9999 */
  url: string;
  onProgress?: (p: BridgeProgress) => void;
  onResult?: (r: BridgeResult) => void;
  onError?: (e: BridgeError) => void;
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useBridge({ url, onProgress, onResult, onError }: UseBridgeOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const seqRef = useRef(0);
  const [status, setStatus] = useState<BridgeStatus>("disconnected");

  // Connect
  const connect = useCallback(() => {
    if (wsRef.current) return;
    setStatus("connecting");

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      seqRef.current = 0;
      // Send scan_start
      ws.send(
        JSON.stringify({
          type: "scan_start",
          device_id: "react-native",
          timestamp_ms: Date.now(),
        })
      );
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        switch (msg.type) {
          case "ack":
            // Frame acknowledged — nothing to do
            break;
          case "progress":
            setStatus("decoding");
            onProgress?.(msg as BridgeProgress);
            break;
          case "result":
            setStatus("done");
            onResult?.(msg as BridgeResult);
            break;
          case "error":
            setStatus("error");
            onError?.(msg as BridgeError);
            break;
        }
      } catch {
        // Ignore malformed server messages
      }
    };

    ws.onerror = () => {
      setStatus("error");
      onError?.({ code: "WS_ERROR", message: "WebSocket connection error" });
    };

    ws.onclose = () => {
      wsRef.current = null;
      if (status !== "done" && status !== "error") {
        setStatus("disconnected");
      }
    };
  }, [url, onProgress, onResult, onError, status]);

  // Disconnect
  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus("disconnected");
  }, []);

  // Send a QR frame
  const sendFrame = useCallback((qrBytes: Uint8Array) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    // Base64-encode the raw QR bytes
    const b64 = uint8ToBase64(qrBytes);
    const seq = seqRef.current++;

    ws.send(
      JSON.stringify({
        type: "frame",
        seq,
        qr_bytes_b64: b64,
        timestamp_ms: Date.now(),
      })
    );
  }, []);

  // Signal end of scanning
  const endScan = useCallback(() => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    ws.send(
      JSON.stringify({
        type: "scan_end",
        total_frames_sent: seqRef.current,
        timestamp_ms: Date.now(),
      })
    );
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  return { status, connect, disconnect, sendFrame, endScan };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Encode Uint8Array to base64 string (React Native compatible). */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
