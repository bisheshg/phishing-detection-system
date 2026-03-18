/**
 * Hardware Fingerprinting — captures non-PII device traits to identify
 * automated probers regardless of IP or User-Agent rotation.
 */

export const getHardwareFingerprint = () => {
  const traits = {};

  // Canvas fingerprint
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('PhishNet-FP', 2, 2);
    traits.canvas = canvas.toDataURL();
  } catch (e) {
    traits.canvas = 'unavailable';
  }

  // WebGL renderer
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl?.getExtension('WEBGL_debug_renderer_info');
    traits.webglRenderer = ext
      ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
      : 'unavailable';
  } catch (e) {
    traits.webglRenderer = 'unavailable';
  }

  // Screen & hardware
  traits.screenResolution = `${window.screen.width}x${window.screen.height}`;
  traits.colorDepth = window.screen.colorDepth;
  traits.cpuCores = navigator.hardwareConcurrency || 'unknown';
  traits.deviceMemory = navigator.deviceMemory || 'unknown';
  traits.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  traits.languages = navigator.languages?.join(',') || navigator.language || 'unknown';

  return traits;
};

/**
 * Returns a SHA-256 hash of the hardware fingerprint traits.
 */
export const generateDeviceHash = async () => {
  try {
    const traits = getHardwareFingerprint();
    const traitString = JSON.stringify(traits);
    const msgBuffer = new TextEncoder().encode(traitString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    // Fallback: random stable ID stored in sessionStorage
    const stored = sessionStorage.getItem('_phishnet_fp');
    if (stored) return stored;
    const fallback = Math.random().toString(36).substr(2, 16);
    sessionStorage.setItem('_phishnet_fp', fallback);
    return fallback;
  }
};
