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

const router = express.Router();

router.post("/register", register);
router.post("/register/verify", verifyOTP);
router.post("/forget/password", forgetPassword);
router.put("/password/reset/:token", resetPassword);
router.post("/login", login);
router.get("/logout", logout);
router.get("/refresh", refreshToken);

export default router;
