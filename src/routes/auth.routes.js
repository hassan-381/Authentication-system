import express from "express";
import {
  register,
  login,
  logout,
  refreshToken,
  verifyOTP,
  forgetPassword,
  resetPassword,
} from "../controllers/auth.controller.js";
import { generateTokens } from "../utils/jwtHelper.js";
import passport from "passport";

const router = express.Router();

router.post("/register", register);
router.post("/register/verify", verifyOTP);
router.post("/forget/password", forgetPassword);
router.put("/password/reset/:token", resetPassword);
router.post("/login", login);
router.get("/logout", logout);
router.get("/refresh", refreshToken);

// GOOGLE
router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = generateToken(req.user._id);
    res.json({ success: true, token, user: req.user });
  }
);

// GITHUB
router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

router.get(
  "/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    const token = generateTokens(req.user._id);
    res.json({ success: true, token, user: req.user });
  }
);

export default router;
