const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const session = require("express-session");
require("dotenv").config();
const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: ["https://medic-web1.vercel.app", "http://localhost:5173"],
    methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
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
    methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    credentials:true,
  })
);

app.set("trust proxy", 1);

app.use(session({
  secret: "tajna",
  resave: true,
  saveUninitialized: true,
  cookie:{secure:false}
  
}));

app.post("/login",  async (req, res) => {
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
      req.session.user = { username: user.username, role: user.role }; 
      //console.log(req.session.user)
      res.status(200).json({ message: "User authenticated successfully." });
    } else {
      res.status(401).send("Invalid username, password, or role.");
    }
  } catch (err) {
    console.error("Error checking user:", err);
    res.status(500).send("Error checking user");
  }
});

const authenticateToken =  (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).send("Access denied.");
  }
  next();
};

app.get("/users", authenticateToken, async(req, res) => {
  console.log("auth",req.session.user)

  try {
    const result = await pool.query("SELECT * FROM users");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error logging out");
    }
    
    res.status(200).json({ message: "Logout successful" });
  });
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

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
