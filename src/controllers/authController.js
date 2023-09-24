const jwt = require("jsonwebtoken");
const adminConfig = require("../secret/ecomerce-duck-acba153957d4.json");
const { private_key } = adminConfig;
const firebaseService = require("../services/firebaseService");

async function signup(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email or password invalid" });
    }
    const userRecord = await firebaseService.createUser(email, password);
    console.log("Successfully created new user:", userRecord);
    res.status(200).json({ message: "User created successfully" });
  } catch (error) {
    console.error("Error creating new user:", error);
    res.status(500).json({ message: "Internal server error", error });
  }
}

async function getInforByEmail(req, res) {
  try {
    const { email } = req.body;
    const inforUser = await firebaseService.getUserByEmail(email);
    // console.log(inforUser);
    res.status(200).json({ message: inforUser });
  } catch (error) {
    console.error("Error get information", error);
    res.status(500).json({ message: "Internal server error", error });
  }
}

async function checkVerifyToken(req, res) {
  try {
    const { token } = req.body;
    const isValid = await firebaseService.checkVerity(token);
    console.log(isValid);
    res.status(200).json({ message: isValid });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
}

async function loginWithEmail(req, res) {
  try {
    const { email, password } = req.body;
    const customToken = await firebaseService.loginWithEmail(email, password);
    console.log(customToken);
    res.status(200).json({ customToken });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

async function LoginwithCustomToken(req, res) {
  try {
    const { customToken } = req.body;
    const userCredential = await firebaseService.loginCustomToken(customToken);
    res.status(200).json({ message: userCredential });
  } catch (error) {
    console.error("Custom token sign-in error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}
// async function signinWithCustomToken(req, res) {
//   try {
//     const { customToken } = req.body;
//     const user = await firebaseService.loginCustomToken(customToken);
//     res.status(200).json({ message: "User signed in successfully", user });
//   } catch (error) {
//     res.status(500).json({ message: "Internal server error" });
//   }
// }

function createJWT(req, res) {
  const { uid } = req.query;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  if (!uid) {
    return res.status(404).json({ message: "UID invalid" });
  }
  try {
    const payload = {
      aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
      iat: currentTimestamp,
      exp: currentTimestamp + 15 * 60,
      iss: "firebase-adminsdk-gqxx7@ecomerce-duck.iam.gserviceaccount.com",
      sub: "firebase-adminsdk-gqxx7@ecomerce-duck.iam.gserviceaccount.com",
      uid: uid,
      claims: {
        expiresIn: {
          expiresIn: currentTimestamp + 15 * 60,
        },
      },
    };

    const privateKey = private_key;

    const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });
    res.status(200).json({ message: token });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: "Internal server error" });
  }
}

async function createToken(req, res) {
  const { uid } = req.body;

  const expirationTime = Math.floor(Date.now() / 1000) + 15 * 60;

  try {
    const customToken = await firebaseService.createCustomToken(uid, {
      expiresIn: expirationTime,
    });
    res.status(200).json({ message: customToken });
  } catch (error) {
    console.error("Error creating custom token:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

async function verifyTokenId(req, res) {
  const { token } = req.body;
  try {
    const validToken = await firebaseService.verifyAccessToken(token);
    res.status(200).json({ message: validToken });
  } catch (error) {
    console.error("Error token is notvalid");
    res.status(500).json({ message: "Internal server error" });
  }
}

async function revokeRefreshToken(req, res) {
  const { uid } = req.body;
  try {
    const refresh = await firebaseService.revokedRefreshToken(uid);
    res.status(200).json({ message: refresh });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
}

async function login(req, res) {
  const { email, password } = req.body;

  try {
    const inforUser = await firebaseService.Login(email, password);
    // console.log();
    res.status(200).json({ message: "access token custom", inforUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
}

async function createSessionLogin(req, res) {
  const idToken = req.body.idToken.toString();
  const csrfToken = req.body.csrfToken.toString();

  if (csrfToken !== req.cookies.csrfToken) {
    res.status(401).send("UNAUTHORIZED REQUEST !");
  }

  try {
    const options = await firebaseService.createSessionLogin(idToken);
    res.cookies("session", sessionCookie, options);
    res.end(JSON.stringify({ status: "success" }));
  } catch (error) {
    res.status(401).send("UNAUTHORIZED REQUEST");
  }
}

module.exports = {
  signup,
  login,
  loginWithEmail,
  // signinWithCustomToken,
  getInforByEmail,
  createToken,
  LoginwithCustomToken,
  checkVerifyToken,
  verifyTokenId,
  createSessionLogin,
  revokeRefreshToken,
  createJWT,
};
