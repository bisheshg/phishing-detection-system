/**
 * Simple Proof-of-Work (PoW) utility to harden submissions against automated probing.
 * This makes it computationally expensive for an attacker to submit thousands of URLs,
 * while being negligible for a legitimate user.
 */

export const generatePoW = async (url, difficulty = 4) => {
  const target = '0'.repeat(difficulty);
  let nonce = 0;
  const startTime = Date.now();

  while (true) {
    const data = `${url}${nonce}`;
    const msgUint8 = new TextEncoder().encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (hashHex.startsWith(target)) {
      return {
        nonce,
        hash: hashHex,
        duration: Date.now() - startTime
      };
    }
    nonce++;
    
    // Safety break for extremely slow devices
    if (nonce > 1000000) break;
  }
};
