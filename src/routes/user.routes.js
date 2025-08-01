import express from "express";
import { isAuthenticated, authorizeRoles } from "../middlewares/auth.js";
import {
  getAllUsers,
  getProfile,
  changePassword,
  updateUser,
  deleteMyAccount,
  deleteUserByAdmin,
} from "../controllers/user.controller.js";

const router = express.Router();

router.get("/profile", isAuthenticated, getProfile);
router.get("/all", isAuthenticated, authorizeRoles("Admin"), getAllUsers);
router.put("/update", isAuthenticated, updateUser);
router.put("/password", isAuthenticated, changePassword);
// User deletes own account
router.delete("/delete/me", isAuthenticated, deleteMyAccount);

// Admin deletes any user by ID
router.delete(
  "/delete/:id",
  isAuthenticated,
  authorizeRoles("Admin"),
  deleteUserByAdmin
);

export default router;
