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
      generateAndSetToken(user,res);
      res
        .status(200)
        .json({ user: user,message: "User authenticated successfully." });
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
    //generateAndSetToken(req.user,res); //prilikom svake akcije, novi token se generise i restratuje se vrijeme za dozvoljenu neaktivnost
    res.setHeader('Access-Control-Expose-Headers', 'Authorization');
    res.setHeader('Authorization', `Bearer ${req.token}`);
    const result = await pool.query(
      "SELECT * FROM users WHERE role != 'admin'"
    );
    res.status(200).json({data: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users");
  }
}

async function logout(req, res) {
  //logout je uvijek moguć neovisno od tokena
  res.status(200).json({ message: "Logout successful" });
}

async function addUser(req, res) {
  const { username, password, name, orders, image_url, date_of_birth } =
    req.body;
    //hesiranje passoworda za bazu
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
    //generateAndSetToken(req.user,res);
    res.setHeader('Access-Control-Expose-Headers', 'Authorization');
    res.setHeader('Authorization', `Bearer ${req.token}`);
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
  //generateAndSetToken(req.user,res)
  res.setHeader('Access-Control-Expose-Headers', 'Authorization');
  res.setHeader('Authorization', `Bearer ${req.token}`);
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      res.status(200).json({data:result.rows[0]});
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
  res.setHeader('Access-Control-Expose-Headers', 'Authorization');
  res.setHeader('Authorization', `Bearer ${req.token}`);
  //vrši se update samo za one atribute koji su promijenjeni, uskalđena je logika sa frontendom, za password ne piše da se treba moći update...
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
    //generateAndSetToken(req.user,res);
    const result = await pool.query(updateUserQuery, values);
    if (result.rows.length > 0) {
      res
        .status(200)
        .json({message: "User updated successfully", user: result.rows[0] });
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
  res.setHeader('Access-Control-Expose-Headers', 'Authorization');
  res.setHeader('Authorization', `Bearer ${req.token}`);
  try {
    //generateAndSetToken(req.user,res);
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
        .json({message: "User blocked successfully", user: result.rows[0] });
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
    //generateAndSetToken(req.user,res);
    const deleteUserQuery = `
        DELETE FROM users
        WHERE id = $1
        RETURNING *
      `;
    const result = await pool.query(deleteUserQuery, [id]);
    if (result.rows.length > 0) {
      res
        .status(200)
        .json({message: "User deleted successfully", user: result.rows[0] });
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
