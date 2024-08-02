const jwt = require('jsonwebtoken');
const { Pool } = require("pg");

const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });

  
const checkUsername = async (req, res, next) => {
  const { username } = req.body;

  if (!username) {
    next();
  } else {
    if (username.length > 15) {
      return res.status(400).send("Username has to be 15 characters or less");
    }

    try {
      const result = await pool.query('SELECT COUNT(*) FROM users WHERE username = $1', [username]);
      if (result.rows[0].count > 0) {
        return res.status(400).send("Username already exists!");
      }
      next();
    } catch (error) {
      return res.status(500).send("Internal server error");
    }
  }
};

const generateAndSetToken = (user, res) => {
  const newToken = jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.cookie("tokenJwtWeb", newToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
};

const authenticateToken = (req, res, next) => {
  const token = req.cookies.tokenJwtWeb;
  if (!token) return res.status(401).send("Access denied.");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid token.");
    generateAndSetToken(user, res);
    req.user = user;
    next();
  });
};

module.exports = {
  checkUsername,
  generateAndSetToken,
  authenticateToken,
};
