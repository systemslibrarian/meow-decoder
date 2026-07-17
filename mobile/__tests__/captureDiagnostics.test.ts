import { diagnoseZeroDecode } from '../src/services/captureDiagnostics';

const BASE = {
  decodeRate: 0,
  zeroDecodeMs: 3_100,
  luminance: 128,
  shakeMagnitude: 0,
  qrCoverage: null,
};

describe('diagnoseZeroDecode', () => {
  it('waits for three seconds and clears when decoding resumes', () => {
    expect(diagnoseZeroDecode({ ...BASE, zeroDecodeMs: 2_999 })).toBeNull();
    expect(diagnoseZeroDecode({ ...BASE, decodeRate: 1 })).toBeNull();
  });

  it('reports excessive motion from accelerometer magnitude', () => {
    expect(diagnoseZeroDecode({ ...BASE, shakeMagnitude: 4 })).toMatchObject({
      reason: 'moving',
    });
  });

  it('reports dark and glare conditions from sampled luminance', () => {
    expect(diagnoseZeroDecode({ ...BASE, luminance: 34 })).toMatchObject({
      reason: 'too-dark',
    });
    expect(diagnoseZeroDecode({ ...BASE, luminance: 226 })).toMatchObject({
      reason: 'glare',
    });
  });

  it('reports distance from the measured QR-to-frame ratio', () => {
    expect(diagnoseZeroDecode({ ...BASE, qrCoverage: 0.86 })).toMatchObject({
      reason: 'too-close',
    });
    expect(diagnoseZeroDecode({ ...BASE, qrCoverage: 0.12 })).toMatchObject({
      reason: 'too-far',
    });
  });

  it('uses an honest framing fallback before QR bounds are available', () => {
    expect(diagnoseZeroDecode(BASE)).toMatchObject({ reason: 'no-geometry' });
  });
});