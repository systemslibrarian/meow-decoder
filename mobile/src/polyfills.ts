/**
 * polyfills.ts — runtime shims for Web APIs missing from React Native's Hermes
 * engine. Imported FIRST in index.js so they exist before any module uses them.
 *
 * TextEncoder / TextDecoder: used by the `qrcode` library
 * (react-native-qrcode-svg) when rendering the QR export on the Export screen.
 * Hermes ships neither, so without these the export screen throws
 * "Property 'TextEncoder' doesn't exist" and the app bounces to Home.
 */

interface MinimalGlobal {
  TextEncoder?: unknown;
  TextDecoder?: unknown;
}

const g = globalThis as unknown as MinimalGlobal;

if (typeof g.TextEncoder === 'undefined') {
  g.TextEncoder = class {
    readonly encoding = 'utf-8';
    encode(input = ''): Uint8Array {
      // unescape(encodeURIComponent(x)) is the classic, Hermes-safe UTF-8 encode.
      const utf8 = unescape(encodeURIComponent(String(input)));
      const bytes = new Uint8Array(utf8.length);
      for (let i = 0; i < utf8.length; i++) bytes[i] = utf8.charCodeAt(i);
      return bytes;
    }
  };
}

if (typeof g.TextDecoder === 'undefined') {
  g.TextDecoder = class {
    readonly encoding = 'utf-8';
    decode(input?: Uint8Array): string {
      if (!input) return '';
      let binary = '';
      for (let i = 0; i < input.length; i++) binary += String.fromCharCode(input[i] as number);
      return decodeURIComponent(escape(binary));
    }
  };
}
