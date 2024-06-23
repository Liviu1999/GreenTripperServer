import pg from "pg";
import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import JWT from "jsonwebtoken";
import { promisify } from "util";
import cors from "cors";

// Create a new pool using the parsed connection details
const { Pool } = pg;

// Loading variables from the .env file
dotenv.config();

console.log("Database connection details:", {
  connectionString: process.env.PROD_DB_DATABASE_URL,
});

const pool = new Pool({
  // user: "uacfd6574l35oo",
  // host: "c9tiftt16dc3eo.cluster-czz5s0kz4scl.eu-west-1.rds.amazonaws.com",
  // database: "dfit4enc7fftph",
  // password: "pc6006872b995beea36cb03e8d41b5d15e4537aeff5ba41622c4d2ffdb94a1681",
  // port: 5433,

  // host: process.env.PROD_DB_HOST,
  // port: process.env.PROD_DB_PROD_DB_PORT,
  // database: process.env.PROD_DB_DATABASE,
  // user: process.env.PROD_DB_USERNAME,
  // password: process.env.PROD_DB_PASSWORD,

  // connectionString: process.env.PROD_DB_DATABASE_URL,
  // ssl: {
  //   rejectUnauthorized: false,
  // },

  host: "ccaml3dimis7eh.cluster-czz5s0kz4scl.eu-west-1.rds.amazonaws.com",
  port: 5432,
  database: "dteaspvf3965d",
  user: "ucagh3m0qau2d8",
  password: "pd3266c0fff9899e737e642ea55a7bfa60aefe9f92ae99a7e3fdc75397a9b1b0a",
  ssl: {
    rejectUnauthorized: false,
  },
});
console.log("-----------PROBLEM just under------------");

pool
  .connect()
  .then(() => {
    console.log("Connected to the database");
  })
  .catch((err) => {
    console.error("Database connection error:", err.stack);
  });
// Launching express
const server = express();

// Promisify the JWT helpers
// => transform callback into Promise based function (async)
const sign = promisify(JWT.sign);
const verify = promisify(JWT.verify);

// Use the json middleware to parse the request body
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send({ name: "utu" });
});

server.get("/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    return res.send(result.rows);
  } catch (error) {
    console.log(error);
    return res.status(500).send({ error: "Error fetching users" });
  }
});

server.post("/api/register", async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !password || !username)
    return res.status(400).send({ error: "Invalid request" });

  try {
    const encryptedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (email, password, username) VALUES ($1, $2, $3)",
      [email, encryptedPassword, username]
    );

    return res.send({ info: "User succesfully created" });
  } catch (err) {
    console.error("Error creating user:", err.message, err.stack);
    return res.status(500).send({ error: "Error creating user" });
  }
});

server.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).send({ error: "Invalid request" });

  const q = await pool.query(
    "SELECT password, user_id, username from users WHERE email=$1",
    [email]
  );

  if (q.rowCount === 0) {
    return res.status(404).send({ error: "This user does not exist" });
  }

  const result = q.rows[0];
  const match = await bcrypt.compare(password, result.password);

  if (!match) {
    return res.status(403).send({ error: "Wrong password" });
  }

  console.log("JWT_SECRET:", process.env.JWT_SECRET);
  console.log("User data for token:", {
    id: result.user_id,
    username: result.username,
    email,
  });

  try {
    const token = await sign(
      { id: result.user_id, username: result.username, email },
      process.env.JWT_SECRET,
      {
        algorithm: "HS512",
        expiresIn: "4h",
      }
    );

    return res.send({ token });
  } catch (err) {
    console.error("Error generating token:", err.message, err.stack);
    return res.status(500).send({ error: "Cannot generate token" });
  }
});

// This middleware will ensure that all subsequent routes include a valid token in the authorization header
// The 'user' variable will be added to the request object, to be used in the following request listeners
server.use(async (req, res, next) => {
  if (!req.headers.authorization) return res.status(401).send("Unauthorized");

  try {
    const decoded = await verify(
      req.headers.authorization.split(" ")[1],
      process.env.JWT_SECRET
    );

    if (decoded !== undefined) {
      req.user = decoded;
      return next();
    }
  } catch (err) {
    console.log(err);
  }

  return res.status(403).send("Invalid token");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () =>
  console.log(`Server is now running in PORT: ${PORT}`)
);
