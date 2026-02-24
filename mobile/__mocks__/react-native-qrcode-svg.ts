/**
 * Mock: react-native-qrcode-svg
 */
import React from 'react';

const QRCode = ({
  value,
  size = 200,
}: {
  value: string;
  size?: number;
}) => React.createElement('View', { testID: 'qrcode', accessibilityLabel: value, style: { width: size, height: size } });

QRCode.displayName = 'MockQRCode';
export default QRCode;
