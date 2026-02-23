// import rateLimit from "express-rate-limit";

// const isUserVerification = (req) => {
//   return (
//     req.originalUrl === "/api/auth/user" ||
//     req.originalUrl.startsWith("/api/auth/user?")
//   );
// };

// export const generalLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: process.env.NODE_ENV === "development" ? 1000 : 100,
//   standardHeaders: true,
//   legacyHeaders: false,
//   message: { error: "Too many requests", code: "RATE_LIMIT_EXCEEDED" },
//   skip: (req) => isUserVerification(req),
// });

// export const authLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: process.env.NODE_ENV === "development" ? 200 : 20,
//   standardHeaders: true,
//   legacyHeaders: false,
//   message: { error: "Too many auth attempts", code: "AUTH_RATE_LIMIT_EXCEEDED" },
//   skip: (req) => isUserVerification(req), // ← Critical fix
// });

// export const reportLimiter = rateLimit({
//   windowMs: 60 * 60 * 1000,
//   max: 10,
//   standardHeaders: true,
//   legacyHeaders: false,
//   message: { error: "Too many reports", code: "REPORT_RATE_LIMIT_EXCEEDED" },
// });