const jwt = require('jsonwebtoken');

const generateAndSetToken = () => {
  const newToken = jwt.sign(
    {},
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  /*res.cookie("tokenJwtWeb", newToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });*/
  return newToken;
};

const authenticateToken = (req, res, next) => {
  const authHeader=req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send("Access denied.");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid token.");
    //generateAndSetToken(user, res);
    req.user = user;
    next();
  });
};

module.exports = {
  generateAndSetToken,
  authenticateToken,
};
