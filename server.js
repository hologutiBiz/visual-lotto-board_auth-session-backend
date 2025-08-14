import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import admin from "firebase-admin";
import { RecaptchaEnterpriseServiceClient } from "@google-cloud/recaptcha-enterprise";

// ✅ Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
});

const credentials = JSON.parse(process.env.RECAPTCHA_SERVICE_ACCOUNT);
const recaptchaClient = new RecaptchaEnterpriseServiceClient({
  credentials,
  projectId: credentials.project_id
});

const app = express();
const PORT = process.env.PORT || 10000;
const SESSION_COOKIE_NAME = "vlb_session";
const SESSION_EXPIRY_MS = 60 * 60 * 24 * 5 * 1000; // 5 days

// ✅ Middleware
app.use(cors({
  origin: [
   "https://auth.visuallottoboard.com",
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
  const recaptchaToken = req.body.recaptchaToken;

  if (!idToken || !recaptchaToken) {
    return res.status(400).send("Missing token(s)");
  }

  try {
    const projectPath = recaptchaClient.projectPath("lotto-forecast-web-db");
    const [assessment] = await recaptchaClient.createAssessment({
      parent: projectPath,
      assessment: {
        event: {
          token: recaptchaToken,
          siteKey: "6LcvUXErAAAAAEezFl2DYdq2Rt9hBwVQ0PqGrQOD",
        }
      }
    });

    const score = assessment.riskAnalysis?.score || 0;
    const reasons = assessment.riskAnalysis?.reasons || [];

    const action = assessment.tokenProperties?.action;
    if (action !== "login" && action !== "google_login") {
      console.warn("Unexpected reCAPTCHA action:", action);
      return res.status(403).send("Invalid reCAPTCHA action");
    }

    if (score < 0.5 || reasons.includes("AUTOMATION")) {
      console.warn("Suspicious reCAPTCHA score:", score, reasons);
      return res.status(403).send("reCAPTCHA verification failed")
    }

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

// Health check route
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`✅ VLB auth backend running on port ${PORT}`);
});
