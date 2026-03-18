/**
 * Proof-of-Work utility — makes large-scale automated URL probing
 * computationally expensive by requiring a valid SHA-256 nonce.
 */

/**
 * Find a nonce whose SHA-256 hash starts with `difficulty` leading zeros.
 * @param {string} challenge - Server-provided challenge string
 * @param {number} difficulty - Number of leading zero hex chars required (default 4)
 * @returns {{ nonce: number, hash: string, duration: number }}
 */
export const generatePoW = async (challenge = 'phishnet', difficulty = 4) => {
  const target = '0'.repeat(difficulty);
  const startTime = Date.now();
  let nonce = 0;

  while (nonce < 1_000_000) {
    const msgBuffer = new TextEncoder().encode(`${challenge}:${nonce}`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    if (hash.startsWith(target)) {
      return { nonce, hash, duration: Date.now() - startTime };
    }
    nonce++;
  }

  // Safety break — return best effort result
  return { nonce, hash: '', duration: Date.now() - startTime };
};
