export function requestLogger(req, res, next) {
  const method = req.method;
  const path = req.originalUrl;

  console.log(`[${method}] ${path}`);

  next();
}