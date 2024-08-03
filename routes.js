const { generateAndSetToken } = require("./jwt");
const { createHash } = require("crypto");
const { isDateValid } = require("./helpers");

const { Pool } = require("pg");
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function login(req, res) {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Username and password are required");
  }
  const hashpassword = createHash("sha256").update(password).digest("hex");

  try {
    const checkUserQuery = `
      SELECT username, role FROM users
      WHERE username = $1 AND password = $2 AND role = 'admin'
    `;
    const values = [username, hashpassword];
    const result = await pool.query(checkUserQuery, values);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const jwt = generateAndSetToken();
      res
        .status(200)
        .json({ user: user, token: jwt, message: "User authenticated successfully." });
    } else {
      res.status(401).send("Invalid username, password, or role.");
    }
  } catch (err) {
    console.error("Error checking user:", err);
    res.status(500).send("Error checking user");
  }
}

async function getUsers(req, res) {
  try {
    const jwt = generateAndSetToken();

    const result = await pool.query(
      "SELECT * FROM users WHERE role != 'admin'"
    );
    res.status(200).json({ token: jwt, data: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users");
  }
}

async function logout(req, res) {
  res.clearCookie("tokenJwtWeb", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.status(200).json({ message: "Logout successful" });
}

async function addUser(req, res) {
  const { username, password, name, orders, image_url, date_of_birth } =
    req.body;
  const hashpassword = createHash("sha256").update(password).digest("hex");
  if (
    !username ||
    !password ||
    !name ||
    orders === undefined ||
    !image_url ||
    !date_of_birth
  ) {
    return res.status(400).send("All fields are required");
  }
  if (!isDateValid(date_of_birth)) {
    return res.status(400).send("Invalid date of birth");
  }

  try {
    const jwt = generateAndSetToken();

    const insertUserQuery = `
        INSERT INTO users (username, password, name, orders, image_url, date_of_birth)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
      `;
    const values = [
      username,
      hashpassword,
      name,
      orders,
      image_url,
      date_of_birth,
    ];
    const result = await pool.query(insertUserQuery, values);
    res
      .status(201)
      .json({
        token: jwt,
        message: "User registered successfully",
        user: result.rows[0],
      });
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).send("Error registering user");
  }
}

async function getUserDetails(req, res) {
  const { id } = req.params;
  const jwt=generateAndSetToken()
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      res.status(200).json({token:jwt, data:result.rows[0]});
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error fetching user details:", err);
    res.status(500).send("Error fetching user details");
  }
}

async function updateUserDetails(req, res) {
  const { id } = req.params;
  const { username, name, orders, date_of_birth, image_url } = req.body;

  let fieldsToUpdate = [];
  let values = [];

  if (username) {
    fieldsToUpdate.push("username = $" + (values.length + 1));
    values.push(username);
  }
  if (name) {
    fieldsToUpdate.push("name = $" + (values.length + 1));
    values.push(name);
  }
  if (orders !== undefined) {
    fieldsToUpdate.push("orders = $" + (values.length + 1));
    values.push(orders);
  }
  if (date_of_birth) {
    if (!isDateValid(date_of_birth))
      return res.status(400).send("Invalid date of birth");

    fieldsToUpdate.push("date_of_birth = $" + (values.length + 1));
    values.push(date_of_birth);
  }
  if (image_url) {
    fieldsToUpdate.push("image_url = $" + (values.length + 1));
    values.push(image_url);
  }

  if (values.length === 0) {
    return res.status(200).json({ message: "No changes" });
  }

  const updateUserQuery = `
    UPDATE users
    SET ${fieldsToUpdate.join(", ")}
    WHERE id = $${values.length + 1}
    RETURNING *
  `;
  values.push(id);

  try {
    const jwt=generateAndSetToken();
    const result = await pool.query(updateUserQuery, values);
    if (result.rows.length > 0) {
      res
        .status(200)
        .json({ token: jwt, message: "User updated successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Error updating user");
  }
}

async function blockUser(req, res) {
  const { status } = req.body;
  const { id } = req.params;
  try {
    const jwt=generateAndSetToken();
    const updateUserQuery = `
        UPDATE users
        SET status = $1
        WHERE id = $2 RETURNING *
      `;
    const values = [status, id];
    const result = await pool.query(updateUserQuery, values);
    if (result.rows.length > 0) {
      res
        .status(200)
        .json({ token: jwt,message: "User blocked successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Error updating user");
  }
}

async function deleteUser(req, res) {
  const { id } = req.params;
  try {
    const jwt=generateAndSetToken();
    const deleteUserQuery = `
        DELETE FROM users
        WHERE id = $1
        RETURNING *
      `;
    const result = await pool.query(deleteUserQuery, [id]);
    if (result.rows.length > 0) {
      res
        .status(200)
        .json({ token:jwt, message: "User deleted successfully", user: result.rows[0] });
    } else {
      res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send("Error deleting user");
  }
}

module.exports = {
  login,
  getUsers,
  logout,
  addUser,
  getUserDetails,
  updateUserDetails,
  blockUser,
  deleteUser,
};
