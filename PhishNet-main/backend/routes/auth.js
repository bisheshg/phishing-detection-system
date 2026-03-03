import express from "express";
import { login, register, userVerification, logout } from "../controllers/auth.js";
import { authRateLimiter, registerRateLimiter } from "../middleware/security.js";
const router = express.Router();

router.post("/register", registerRateLimiter, register);
router.post("/login", authRateLimiter, login);

// Session check and logout are NOT rate-limited — React calls /user on every page load
router.get("/user", userVerification);
router.get("/logout", logout);


export default router