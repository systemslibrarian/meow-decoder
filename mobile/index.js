/**
 * meow-decoder Mobile — Entry Point
 *
 * SECURITY: This app acquires camera permission only.
 * No network, no microphone, no location, no broad storage access.
 * All frame data lives in memory only, cleared on session end or background.
 */

import './src/polyfills'; // Hermes shims (TextEncoder/TextDecoder) — must be first.
import { AppRegistry } from 'react-native';
import App from './src/App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
