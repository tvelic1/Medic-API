const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: ["https://medic-web1.vercel.app", "http://localhost:5173"],
    methods: ["GET", "POST", "OPTIONS","PUT","DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-cookie"],
    credentials: true,
  })
);

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.options(
  "*",
  cors({
    origin: ["https://medic-web1.vercel.app", "http://localhost:5173"],
    methods: ["GET", "POST", "OPTIONS","PUT","DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-cookie"],
    credentials: true,
  })
);

app.set("trust proxy", 1);

app.post("/login", async (req, res) => {

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Username and password are required");
  }
  try {
    const checkUserQuery = `
      SELECT username, role FROM users
      WHERE username = $1 AND password = $2 AND role = 'admin'
    `;
    const values = [username, password];
    const result = await pool.query(checkUserQuery, values);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      generateAndSetToken(user, res);
      res.status(200).json({ message: "User authenticated successfully." });
    }
     else {
      res.status(401).send("Invalid username, password, or role.");
    }
  } catch (err) {
    console.error("Error checking user:", err);
    res.status(500).send("Error checking user");
  }

});

const checkUsername = async (req, res, next) => {
  const {username}=req.body;

  if(!username) next();

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
;

const generateAndSetToken = (user, res) => {

  const newToken = jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.cookie("tokenJwtWeb", newToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

};

const authenticateToken =  (req, res, next) => {

  const token = req.cookies.tokenJwtWeb;
  if (!token) return res.status(401).send("Access denied.");
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid token.");
    generateAndSetToken(user, res);
    req.user = user;
    next();
  });

};

app.get("/users", authenticateToken, async (req, res) => {

  try {
    const result = await pool.query("SELECT * FROM users WHERE role != 'admin'");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users");
  }

});
app.post("/logout", (req, res) => {
  res.clearCookie("tokenJwtWeb", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  res.status(200).json({ message: "Logout successful" });
});


app.post("/register",authenticateToken, checkUsername, async (req, res) => {
  const { username, password, name, orders, image_url, date_of_birth } = req.body;
  if (!username || !password || !name || orders === undefined || !image_url || !date_of_birth) {
    return res.status(400).send("All fields are required");
  }
  try {
    const insertUserQuery = `
      INSERT INTO users (username, password, name, orders, image_url, date_of_birth)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `;
    const values = [username, password, name, orders, image_url, date_of_birth];
    const result = await pool.query(insertUserQuery, values);
    res.status(201).json({ message: "User registered successfully", user: result.rows[0] });
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).send("Error registering user");
  }
});

app.get("/users/details/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error fetching user details:", err);
    res.status(500).send("Error fetching user details");
  }
});

app.put("/users/details/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { username, name, orders, date_of_birth, image_url} = req.body;
  try {
    const updateUserQuery = `
      UPDATE users
      SET username = $1, name = $2, orders = $3, date_of_birth=$4, image_url = $5
      WHERE id = $6 RETURNING *
    `;
    const values = [username, name, orders, date_of_birth, image_url, id];
    const result = await pool.query(updateUserQuery, values);
    if (result.rows.length > 0) {
      res.status(200).json({ message: "User updated successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Error updating user");
  }
});

app.put("/users/block/:id", authenticateToken, async (req, res) => {
  const{status}=req.body;
  const { id } = req.params;
  try {
    const updateUserQuery = `
      UPDATE users
      SET status = $1
      WHERE id = $2 RETURNING *
    `;
    const values = [status,id];
    const result = await pool.query(updateUserQuery, values);
    if (result.rows.length > 0) {
      res.status(200).json({ message: "User blocked successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Error updating user");
  }
});

app.delete("/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deleteUserQuery = `
      DELETE FROM users
      WHERE id = $1
      RETURNING *
    `;
    const result = await pool.query(deleteUserQuery, [id]);
    if (result.rows.length > 0) {
      res.status(200).json({ message: "User deleted successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send("Error deleting user");
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
