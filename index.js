```javascript
const pool = require("./db");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const corsOptions = {
    origin: [
        "https://pieblox.github.io",
        "https://coalblox.github.io"
    ],
    credentials: true
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// PASSWORD HASHING
// =========================

function hashPassword(password) {
    return new Promise(function (resolve, reject) {
        const salt = crypto.randomBytes(16).toString("hex");

        crypto.scrypt(password, salt, 64, function (err, derivedKey) {
            if (err) {
                reject(err);
                return;
            }

            resolve(
                salt + ":" + derivedKey.toString("hex")
            );
        });
    });
}

function verifyPassword(password, storedHash) {
    return new Promise(function (resolve, reject) {
        if (!storedHash || !storedHash.includes(":")) {
            resolve(false);
            return;
        }

        const parts = storedHash.split(":");
        const salt = parts[0];
        const key = parts[1];

        if (!salt || !key) {
            resolve(false);
            return;
        }

        const storedKey = Buffer.from(key, "hex");

        crypto.scrypt(password, salt, 64, function (err, derivedKey) {
            if (err) {
                reject(err);
                return;
            }

            if (storedKey.length !== derivedKey.length) {
                resolve(false);
                return;
            }

            resolve(
                crypto.timingSafeEqual(
                    storedKey,
                    derivedKey
                )
            );
        });
    });
}

// =========================
// SESSION HELPERS
// =========================

function createSessionToken() {
    return crypto.randomBytes(32).toString("hex");
}

function hashSessionToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function getSessionToken(req) {
    const cookieHeader = req.headers.cookie;

    if (!cookieHeader) {
        return null;
    }

    const cookies = cookieHeader.split(";");

    for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();

        if (cookie.startsWith("session=")) {
            return decodeURIComponent(
                cookie.substring("session=".length)
            );
        }
    }

    return null;
}

async function createSession(userId) {
    const token = createSessionToken();
    const tokenHash = hashSessionToken(token);

    const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
    );

    await pool.query(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        [userId, tokenHash, expiresAt]
    );

    return token;
}

async function findUser(username) {
    const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
    );

    return result.rows[0];
}

async function getUserFromSession(token) {
    if (!token) {
        return null;
    }

    const tokenHash = hashSessionToken(token);

    const result = await pool.query(
        "SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()",
        [tokenHash]
    );

    return result.rows[0] || null;
}

// =========================
// LOGIN PAGE TEST
// =========================

app.get("/login/v1", function (req, res) {
    res.json({
        success: true,
        message: "Login endpoint exists. Use POST."
    });
});

// =========================
// LOGIN
// =========================

app.post("/login/v1", async function (req, res) {
    const username = req.body && req.body.username;
    const password = req.body && req.body.password;

    // NEVER log the password.
    console.log(
        "Login attempt:",
        username || "(missing username)"
    );

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        const user = await findUser(username);

        if (!user) {
            return res.json({
                success: false,
                message: "Invalid username or password"
            });
        }

        const validPassword = await verifyPassword(
            password,
            user.password
        );

        if (!validPassword) {
            return res.json({
                success: false,
                message: "Invalid username or password"
            });
        }

        const sessionToken = await createSession(user.id);

        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/"
        });

        console.log("Logged in:", user.username);

        return res.json({
            success: true,
            username: user.username,
            redirect: "https://pieblox.github.io/games"
        });

    } catch (err) {
        console.error("Login error:", err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// =========================
// SESSION CHECK
// =========================

app.get("/session", async function (req, res) {
    try {
        const token = getSessionToken(req);
        const user = await getUserFromSession(token);

        if (!user) {
            return res.json({
                success: false,
                loggedIn: false
            });
        }

        return res.json({
            success: true,
            loggedIn: true,
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (err) {
        console.error("Session error:", err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// =========================
// LOGOUT
// =========================

app.post("/logout", async function (req, res) {
    try {
        const token = getSessionToken(req);

        if (token) {
            const tokenHash = hashSessionToken(token);

            await pool.query(
                "DELETE FROM sessions WHERE token_hash = $1",
                [tokenHash]
            );
        }

        res.clearCookie("session", {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            path: "/"
        });

        return res.json({
            success: true,
            message: "Logged out"
        });

    } catch (err) {
        console.error("Logout error:", err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// =========================
// DATABASE TEST
// =========================

app.get("/dbtest", async function (req, res) {
    try {
        const result = await pool.query("SELECT NOW()");

        return res.json({
            success: true,
            time: result.rows[0]
        });

    } catch (err) {
        console.error("Database error:", err);

        return res.status(500).json({
            success: false,
            message: "Database error"
        });
    }
});

// =========================
// SIGNUP
// =========================

app.post("/signup/v1", async function (req, res) {
    const username = req.body && req.body.username;
    const password = req.body && req.body.password;

    // NEVER log the password.
    console.log(
        "Signup request:",
        username || "(missing username)"
    );

    try {
        if (!username || !password) {
            return res.json({
                success: false,
                message: "Username and password are required"
            });
        }

        if (username.length < 3 || username.length > 20) {
            return res.json({
                success: false,
                message: "Invalid username"
            });
        }

        if (password.length < 8) {
            return res.json({
                success: false,
                message: "Password must be at least 8 characters"
            });
        }

        const existingUser = await pool.query(
            "SELECT id FROM users WHERE username = $1",
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.json({
                success: false,
                message: "Username already exists"
            });
        }

        const passwordHash = await hashPassword(password);

        const result = await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
            [username, passwordHash]
        );

        const user = result.rows[0];

        const sessionToken = await createSession(user.id);

        res.cookie("session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 30 * 24 * 60 * 60 * 1000,
            path: "/"
        });

        return res.json({
            success: true,
            userId: user.id,
            username: user.username,
            message: "Account created!"
        });

    } catch (err) {
        console.error("Signup error:", err);

        return res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

// =========================
// CAPTCHA
// =========================

app.post("/captcha/validate/signup", function (req, res) {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});

app.post("/captcha/validate/login", function (req, res) {
    res.json({
        success: true,
        message: "Captcha passed"
    });
});

// =========================
// USERNAME CHECKER
// =========================

app.get(
    "/UserCheck/checkifinvalidusernameforsignup",
    function (req, res) {
        const username = req.query.username;

        res.json({
            success: true,
            isValid: true,
            IsValid: true,
            username: username || "",
            message: "Username is available"
        });
    }
);

// =========================
// DEBUG ROUTES
// =========================

app.get("/routes", function (req, res) {
    res.json({
        routes: [
            "GET /",
            "POST /device/initialize",
            "GET /login/v1",
            "POST /login/v1",
            "POST /signup/v1",
            "POST /logout",
            "GET /session",
            "POST /captcha/validate/login",
            "POST /captcha/validate/signup",
            "GET /UserCheck/checkifinvalidusernameforsignup"
        ]
    });
});

// =========================
// API HOMEPAGE
// =========================

app.get("/", function (req, res) {
    res.json({
        success: true,
        message: "Pieblox API is running",
        version: "1.0",
        time: new Date()
    });
});

// =========================
// DEVICE INITIALIZE
// =========================

app.post("/device/initialize", function (req, res) {
    res.json({
        success: true,
        message: "Device initialized"
    });
});

// =========================
// 404
// =========================

app.use(function (req, res) {
    console.log("404:", req.method, req.url);

    res.status(404).json({
        success: false,
        message: "Endpoint not found",
        method: req.method,
        path: req.path
    });
});

// =========================
// START SERVER
// =========================

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", function () {
    console.log("Server running on port " + port);
});
```
