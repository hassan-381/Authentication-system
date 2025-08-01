import jwt from "jsonwebtoken";

export const generateTokens = async (user, message, statusCode, res) => {
  const token = user.generateJsonWebToken();

  user.token = token;
  await user.save({ validateBeforeSave: false });

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    }
  );

  const cookieExpiresIn = 1 * 60 * 60 * 1000; // 1 hour

  res
    .status(statusCode)
    .cookie("token", token, {
      expires: new Date(Date.now() + cookieExpiresIn),
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })
    .json({
      success: true,
      token,
      message,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: user.token,
      },
    });
};
