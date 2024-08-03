const jwt = require('jsonwebtoken');

const generateAndSetToken = (user,res) => {
  const newToken = jwt.sign(
    {username:user.username, role:user.role},
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  /*res.cookie("tokenJwtWeb", newToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });*/
  res.setHeader('Access-Control-Expose-Headers', 'Authorization');
  res.setHeader('Authorization', `Bearer ${newToken}`);
};

const authenticateToken = (req, res, next) => {
  const authHeader=req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send("Access denied.");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid token.");
    //generateAndSetToken(user, res);
    req.user = user;
    //console.log(user);
    next();
  });
};

module.exports = {
  generateAndSetToken,
  authenticateToken,
};
