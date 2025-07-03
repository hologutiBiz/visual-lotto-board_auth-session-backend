import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import admin from "firebase-admin";

// ✅ Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert("./firebase/serviceAccountKey.json")
});

const app = express();
const PORT = process.env.PORT || 10000;
const SESSION_COOKIE_NAME = "allow_free_user_to_view_results";
const SESSION_EXPIRY_MS = 60 * 60 * 24 * 5 * 1000; // 5 days

// ✅ Middleware
app.use(cors({
  origin: [
   "https://app.visuallottoboard.com",
   "https://premier-lotto-babaijebu-results.visuallottoboard.com",
   "https://visuallottoboard.com",
   
    // Add more if needed
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// ✅ Set Session Route
app.post("/setSession", async (req, res) => {
  const idToken = req.body.token;

  if (!idToken) {
    return res.status(400).send("Missing token");
  }

  try {
    const sessionCookie = await admin.auth().createSessionCookie(idToken, {
      expiresIn: SESSION_EXPIRY_MS
    });

    res.cookie(SESSION_COOKIE_NAME, sessionCookie, {
      maxAge: SESSION_EXPIRY_MS,
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      domain: ".visuallottoboard.com" // ✅ works across subdomains
    });

    res.status(200).send("Session cookie set");
  } catch (error) {
    console.error("Set session failed:", error);
    res.status(401).send("Unauthorized");
  }
});

// ✅ Verify Session Route
app.get("/verifySession", async (req, res) => {
  const sessionCookie = req.cookies?.vlb_session;

  if (!sessionCookie) {
    return res.status(401).send("No session cookie found");
  }

  try {
    const decodedToken = await admin.auth().verifySessionCookie(sessionCookie, true);

    res.status(200).json({
      uid: decodedToken.uid,
      email: decodedToken.email,
      name: decodedToken.name,
      picture: decodedToken.picture
    });
  } catch (error) {
    console.error("Session verification failed:", error);
    res.status(401).send("Session invalid or expired");
  }
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`✅ VLB auth backend running on port ${PORT}`);
});
