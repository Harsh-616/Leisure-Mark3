require("dotenv").config(); // Load environment variables from .env
const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const { google } = require("googleapis");

// Load environment variables from .env
const PASSWORDS_SHEET_ID = process.env.PASSWORDS_SHEET_ID;
const PRICES_SHEET_ID = process.env.PRICES_SHEET_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CREDENTIALS = JSON.parse(
  Buffer
    .from(process.env.GOOGLE_SERVICE_ACCOUNT_KEY, "base64")
    .toString("utf-8")
);

// Correct newline handling for private_key
// GOOGLE_CREDENTIALS.private_key = GOOGLE_CREDENTIALS.private_key.replace(
//   /\\n/g,
//   '\n'
// );

// Initialize Express app
const app = express();
app.use(express.static(path.join(__dirname, "public"))); // Serve static files from public directory
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded form data
app.use("/scripts", express.static(__dirname)); // Serve root directory under /scripts
// Function to authenticate with Google Sheets API
async function getSheetData(sheetId, range) {
  console.log("get sheet data called");
  const auth = new google.auth.JWT(
    GOOGLE_CREDENTIALS.client_email,
    null,
    GOOGLE_CREDENTIALS.private_key,
    ["https://www.googleapis.com/auth/spreadsheets.readonly"]
  );

  const sheets = google.sheets({ version: "v4", auth });
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: range,
  });
  console.log("sheet data extracted");
  return response.data.values;
}

// Route for user authentication
app.post("/authenticate", async (req, res) => {
  const { username, password, deviceIdentifier } = req.body;

  try {
    // Fetch user data from Google Sheets
    const data = await getSheetData(PASSWORDS_SHEET_ID, "Sheet1!A2:E100");
    const users = data.map((row) => ({
      username: row[0],
      password: row[1],
      allowedDevice: row[2],
      phone: row[3],
      designation: row[4],
    }));

    // Find user by username and password
    const user = users.find(
      (user) => user.username === username && user.password === password
    );

    // Validate user and device
    if (user && user.allowedDevice === deviceIdentifier) {
      const token = jwt.sign(
        {
          username: user.username,
          phone: user.phone,
          designation: user.designation,
        },
        JWT_SECRET,
        { expiresIn: "1h" } // Token expires in 1 hour
      );

      // Send token along with redirection flag
      res.json({ success: true, token });
    } else {
      res.status(401).send("Invalid credentials or device identifier.");
    }
  } catch (error) {
    console.error("Error authenticating user:", error);
    res.status(500).send("Internal server error.");
  }
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Access denied. No token provided.");
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send("Invalid token.");
    }
    req.user = user; // Attach user data to request object
    next();
  });
}

// Protected route to fetch user data
app.get("/get-user-data", authenticateToken, (req, res) => {
  const { username, phone, designation } = req.user;
  res.json({ username, phone, designation });
});

// Protected route to fetch price data
app.get("/get-data", authenticateToken, async (req, res) => {
  try {
    const data = await getSheetData(PRICES_SHEET_ID, "Sheet1!A1:Z100");
    res.json({ data });
  } catch (error) {
    console.error("Error fetching price data:", error);
    res.status(500).json({ error: "Failed to retrieve data." });
  }
});

// Serve static HTML files
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

app.get("/index.html", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/login.html`);
});
