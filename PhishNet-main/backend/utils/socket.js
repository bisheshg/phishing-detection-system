/**
 * Socket.IO singleton — breaks the circular dependency between
 * server.js (which creates io) and controllers that need to emit events.
 */
let _io = null;

export const setIo = (io) => { _io = io; };
export const getIo = () => _io;
