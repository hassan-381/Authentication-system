import User from "../models/user.model.js";
import ErrorHandler from "../utils/ErrorHandler.js";
import { catchAsyncErrors } from "../middlewares/catchAsyncErrors.js";

// Get user profile
export const getProfile = catchAsyncErrors(async (req, res) => {
  const user = await User.findById(req.user._id).select("-password");
  res.status(200).json({ success: true, user });
});

// Get all users (admin only)
export const getAllUsers = catchAsyncErrors(async (req, res) => {
  const users = await User.find({ isDeleted: false }).select("-password");
  res.status(200).json({ success: true, users });
});

// Update user details
export const updateUser = catchAsyncErrors(async (req, res) => {
  const { name, email } = req.body;
  const user = await User.findByIdAndUpdate(
    req.user._id,
    { name, email },
    { new: true, runValidators: true }
  );
  res.status(200).json({ success: true, user });
});

// Change password
export const changePassword = catchAsyncErrors(async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user._id).select("+password");

  if (!user) {
    return next(new ErrorHandler("User not found", 404));
  }

  const isMatch = await user.comparePassword(oldPassword);

  if (!isMatch) {
    return next(new ErrorHandler("Old password is incorrect", 400));
  }

  user.password = newPassword;
  await user.save();

  res.status(200).json({
    success: true,
    message: "Password changed successfully",
  });
});

// Delete my account
export const deleteMyAccount = catchAsyncErrors(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user._id, { isDeleted: true });
  res.status(200).json({
    success: true,
    message: "Your account has been deleted",
  });
});

// 🔐 Admin deletes any user by ID
export const deleteUserByAdmin = catchAsyncErrors(async (req, res, next) => {
  if (req.user.role.toLowerCase() !== "admin") {
    return next(new ErrorHandler("You are not authorized", 403));
  }
  console.log("Authenticated user:", req.user);

  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new ErrorHandler("User not found", 404));
  }

  await User.findByIdAndUpdate(req.params.id, { isDeleted: true });

  res.status(200).json({
    success: true,
    message: "User has been deleted (delete by admin)",
  });
});
