import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import ErrorHandler from "../utils/ErrorHandler.js";
import { catchAsyncErrors } from "../middlewares/catchAsyncErrors.js";
import { generateTokens } from "../utils/jwtHelper.js";

export const register = catchAsyncErrors(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return next(new ErrorHandler("All fields are required", 400));
  }

  const userExists = await User.findOne({ email });
  if (userExists) {
    return next(new ErrorHandler("Email already exists", 400));
  }

  const user = await User.create({
    name,
    email,
    password,
    role: role?.toLowerCase(), // <-- FIX HERE
  });

  generateTokens(user, "Registered", 201, res);
});

export const login = catchAsyncErrors(async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.comparePassword(password))) {
    return next(new ErrorHandler("Invalid credentials", 401));
  }

  generateTokens(user, "Logged in", 200, res);
});

export const logout = catchAsyncErrors(async (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ success: true, message: "Logged out" });
});

export const refreshToken = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.refreshToken;
  if (!token) return next(new ErrorHandler("Refresh token not found", 401));

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_SECRET);

    // ✅ Find full user object using decoded ID
    const user = await User.findById(decoded.id);
    if (!user) return next(new ErrorHandler("User not found", 404));

    // ✅ Now safely call generateTokens
    generateTokens(user, "Token refreshed", 200, res);
  } catch (error) {
    return next(new ErrorHandler("Invalid refresh token", 401));
  }
});
