const pool = require("./db");
const express = require("express");
const cors = require("cors");

const app = express();

const corsOptions = {
    origin: "https://pieblox.github.io",
    credentials: true
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function findUser(username) {
    const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
    );

    return result.rows[0];
}

// Login page test
app.get("/login/v1", (req, res) => {
    res.json({
        success: true,
        message: "Login endpoint exists. Use POST."
    });
});


// Login
app.post("/login/v1", async (req, res) => {
    console.log("LOGIN BODY:", req.body);

    const { username, password } = req.body || {};

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        const user = await findUser(username);

        if (!user || user.password !== password) {
            return res.json({
                success: false,
                message: "Invalid username or password"
            });
        }

        console.log("Logged in:", user.username);

        return res.json({
            success: true,
            redirect: "https://pieblox.github.io/games"
        });

    } catch (err) {
        console.error(err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});


// dbtest
app.get("/dbtest", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");

        res.json({
            success: true,
            time: result.rows[0]
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});


// Signup
app.post("/signup/v1", async (req, res) => {
    const { username, password } = req.body || {};

    console.log("Signup request:", req.body);

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        const existingUser = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.json({
                success: false,
                message: "Username already exists"
            });
        }

        const result = await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
            [username, password]
        );

        const user = result.rows[0];

        res.json({
            success: true,
            userId: user.id,
            username: user.username,
            message: "Account created!"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});


// Captcha
app.post("/captcha/validate/signup", (req, res) => {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});

app.post("/captcha/validate/login", (req, res) => {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});


// Username checker
app.get("/UserCheck/checkifinvalidusernameforsignup", (req, res) => {
    const username = req.query.username;

    res.json({
        success: true,
        isValid: true,
        IsValid: true,
        username: username || "",
        message: "Username is available"
    });
});


// Debug routes
app.get("/routes", (req, res) => {
    res.json({
        routes: [
            "GET /",
            "POST /device/initialize",
            "GET /login/v1",
            "POST /login/v1",
            "POST /signup/v1",
            "POST /captcha/validate/login",
            "POST /captcha/validate/signup",
            "GET /UserCheck/checkifinvalidusernameforsignup"
        ]
    });
});


// API homepage
app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Pieblox API is running",
        version: "1.0",
        time: new Date()
    });
});


// Device initialize
app.post("/device/initialize", (req, res) => {
    res.json({
        success: true,
        message: "Device initialized"
    });
});


// 404 (MUST STAY LAST)
app.use((req, res) => {
    console.log("404:", req.method, req.url);

    res.status(404).json({
        success: false,
        message: "Endpoint not found",
        method: req.method,
        path: req.path
    });
});


const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
    console.log(`Server running on port ${port}`);
});

// redeploy
