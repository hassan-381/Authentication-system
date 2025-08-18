import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import ErrorHandler from "../utils/ErrorHandler.js";
import { catchAsyncErrors } from "../middlewares/catchAsyncErrors.js";
import { generateTokens } from "../utils/jwtHelper.js";
import { sendEmail } from "../utils/sendEmail.js";
import crypto from "crypto";

export const register = catchAsyncErrors(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return next(new ErrorHandler("All fields are required", 400));
  }

  // ✅ check if already verified account exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new ErrorHandler("Email already exists", 400));
  }

  // ✅ create user
  const user = await User.create({
    name,
    email,
    password,
    role: role?.toLowerCase(),
  });

  // ✅ generate verification code
  const verificationCode = user.generateVerificationCode();
  await user.save();

  // ✅ send verification email
  const message = `
    <h1>Hello ${name}</h1>
    <p>Your verification code is:</p>
    <h2>${verificationCode}</h2>
    <p>This code will expire in 10 minutes.</p>
  `;

  try {
    await sendEmail({
      email: user.email,
      subject: "Email Verification Code",
      message,
    });

    res.status(201).json({
      success: true,
      message: `Verification code sent successfully to ${user.email}`,
    });
  } catch (err) {
    user.verificationCode = undefined;
    user.verificationCodeExpire = undefined;
    await user.save();

    return next(new ErrorHandler("Email could not be sent", 500));
  }
});

export const verifyOTP = catchAsyncErrors(async (req, res, next) => {
  const { email, otp } = req.body;
  try {
    const userAllEntries = await User.find({
      email: email,
      accountVerified: false,
    }).sort({ createdAt: -1 });

    if (!userAllEntries || userAllEntries.length === 0) {
      return next(new ErrorHandler("User not found", 404));
    }

    let user;
    if (userAllEntries.length > 1) {
      user = userAllEntries[0];

      await User.deleteMany({
        _id: { $ne: user._id },
        $or: [{ email, accountVerified: false }],
      });
    } else {
      user = userAllEntries[0];
    }

    if (user.verificationCode !== Number(otp)) {
      return next(new ErrorHandler("Invalid OTP", 400));
    }

    const currentTime = new Date();
    const verificationCodeExpirationTime = new Date(
      user.verificationCodeExpire
    ).getTime();

    if (currentTime > verificationCodeExpirationTime) {
      return next(new ErrorHandler("OTP expired", 400));
    }

    user.accountVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpire = null;
    await user.save({ validateModifiedOnly: false });

    generateTokens(user, "User verified successfully", 200, res);
  } catch (error) {
    console.log("Actual error:", error);
    return next(new ErrorHandler("Internal Server Error", 400));
  }
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

export const forgetPassword = catchAsyncErrors(async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({
    email: req.body.email,
    accountVerified: true,
  });
  if (!user) {
    return next(new ErrorHandler("User not found", 404));
  }

  const resetToken = await user.generateResetPasswordToken();
  await user.save({ validateModifiedOnly: false });

  const resetPasswordUrl = `${process.env.FRONTEND_URL}/password/reset/${resetToken}`;

  const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\n If you have not requested this email then, please ignore it.`;

  try {
    await sendEmail({
      email: user.email,
      subject: `Auth User Password Recovery`,
      message,
    });
    res.status(200).json({
      success: true,
      message: `Email sent to ${user.email} successfully`,
    });
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save({ validateModifiedOnly: false });
    return next(
      new ErrorHandler(
        error.message ? error.message : "Cannot send email password token.",
        500
      )
    );
  }
});

export const resetPassword = catchAsyncErrors(async (req, res, next) => {
  const { token } = req.params;
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });
  if (!user) {
    return next(
      new ErrorHandler(
        "Reset password token is invalid or has been expired.",
        400
      )
    );
  }

  if (req.body.password !== req.body.confirmPassword) {
    return next(
      new ErrorHandler("Password & confirm password do not match.", 400)
    );
  }

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;
  await user.save({ validateModifiedOnly: false });

  generateTokens(user, "Password reset successfully", 200, res);
});
