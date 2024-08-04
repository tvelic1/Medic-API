const { Pool } = require("pg");

const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
    ssl: {
      rejectUnauthorized: false,
    },
  });

  
const checkUsername = async (req, res, next) => {
  const { username } = req.body;
  //osiguravanje da je username jedinstven
  if (!username) {
    return next();
  } 

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
  
};

function isDateValid(dateString) {

    const dateOfBirth = new Date(dateString);
    const currentDate = new Date();
    return dateOfBirth <= currentDate; 
  }


module.exports = {
  checkUsername,
  isDateValid,
};
