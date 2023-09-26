const admin = require("firebase-admin");

const appAdmin = require("../firebase/adminConfig");
async function verifyAccessToken(req, res, next) {
  try {
    const accessToken = req.headers["authorization"];
    const decodedToken = await admin.auth().verifyIdToken(accessToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid access token" });
  }
}

module.exports = verifyAccessToken;
