const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const app = express();
app.use(express.json());
app.use(cookieParser());
const {authenticateToken } = require("./jwt");
const { checkUsername} = require("./helpers");
const routes=require("./routes")

app.use(
  cors({
    origin: ["https://medic-web1.vercel.app", "http://localhost:5173"],
    methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-cookie"],
    credentials: true,
  })
);


app.options(
  "*",
  cors({
    origin: ["https://medic-web1.vercel.app", "http://localhost:5173"],
    methods: ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["set-cookie"],
    credentials: true,
  })
);

app.set("trust proxy", 1);

app.post("/login", routes.login)
app.get("/users", authenticateToken, routes.getUsers)
app.post("/logout", routes.logout)
app.post("/register", authenticateToken, checkUsername, routes.addUser)
app.get("/users/details/:id", authenticateToken, routes.getUserDetails)
app.put("/users/details/:id",authenticateToken,checkUsername,routes.updateUserDetails)
app.put("/users/block/:id", authenticateToken, routes.blockUser)
app.delete("/users/:id", authenticateToken, routes.deleteUser)
 
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
