class ErrorHandler extends Error {
  constructor(message, statusCode, data = null) {
    super(message);
    this.statusCode = statusCode;
    this.data = data;
  }
}

export const errorMiddleware = (err, req, res, next) => {
  console.log(err);
  err.message = err.message || "Internal Server Error";
  err.statusCode = err.statusCode || 500;

  if (err.name === "JsonWebTokenError") err.message = "Invalid Token";
  if (err.name === "TokenExpiredError") err.message = "Token Expired";
  if (err.name === "CastError") err.message = `Invalid ${err.path}`;

  const errorMessage = err.data
    ? Object.values(err.data)
        .map((error) => error.message)
        .join(" ")
    : err.message;

  return res.status(err.statusCode).json({
    success: false,
    message: errorMessage,
    data: err.data || null,
  });
};

export default errorMiddleware;
export { ErrorHandler };
