// auth.middleware.js

import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import ErrorHandler from "../utils/ErrorHandler.js";
import { catchAsyncErrors } from "./catchAsyncErrors.js";

export const isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

  if (!token) {
    return next(new ErrorHandler("Login first to access this resource", 401));
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
  req.user = await User.findById(decoded.id).select("-password");
  next();
});

export const authorizeRoles =
  (...roles) =>
  (req, res, next) => {
    const userRole = req.user.role?.toLowerCase();
    const allowedRoles = roles.map((r) => r.toLowerCase());

    if (!allowedRoles.includes(userRole)) {
      return next(new ErrorHandler("Forbidden", 403));
    }
    next();
  };
