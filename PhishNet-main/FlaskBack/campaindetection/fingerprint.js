/**
 * Advanced Client Fingerprinting
 * Captures non-pii hardware and software traits to identify automated probers
 * bypass basic PoW.
 */

export const getHardwareFingerprint = () => {
  const traits = {
    canvas: null,
    webgl: null,
    renderer: null,
    resolution: `${window.screen.width}x${window.screen.height}`,
    cores: navigator.hardwareConcurrency || 'unknown',
    memory: navigator.deviceMemory || 'unknown',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    languages: navigator.languages.join(','),
  };

  try {
    // 1. Canvas Fingerprint
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125,1,62,20);
    ctx.fillStyle = "#069";
    ctx.fillText("PhishNet-Guardian-v1", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("Adversarial-Resistant", 4, 17);
    traits.canvas = canvas.toDataURL();

    // 2. WebGL Fingerprint
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      traits.renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      traits.webgl = gl.getParameter(gl.VERSION);
    }
  } catch (e) {
    console.error("Fingerprint capture restricted", e);
  }

  return traits;
};

export const generateDeviceHash = async () => {
  const traits = getHardwareFingerprint();
  const msgUint8 = new TextEncoder().encode(JSON.stringify(traits));
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};
