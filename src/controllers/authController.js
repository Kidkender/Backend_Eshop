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
    res.status(500).json({ message: error.message });
  }
}

async function resetPassword(req, res) {
  const { email } = req.body;
  console.log(email);
  if (!email) {
    return res.status(401).json({ message: "Email invalid" });
  }
  try {
    const userRecord = await firebaseService.resetPasswd(email);
    console.log("infor", userRecord);
    return userRecord
      ? res
          .status(200)
          .json({ message: "Send mail reset password successfully" })
      : res.status(401).json({ message: "User is not exist" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
}

async function getInforByEmail(req, res) {
  try {
    const { email } = req.body;
    const inforUser = await firebaseService.getUserByEmail(email);
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

    return userCredential
      ? res.status(200).json({ message: userCredential })
      : res.status(403).json({ message: "Token invalid" });
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
      // aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
      aud: "projects/ecomerce-duck",
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
  console.log("token", token);
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
  if (!uid) {
    res.status(404).json({ message: "UID invalid" });
  }
  try {
    const refresh = await firebaseService.revokedRefreshToken(uid);
    return refresh
      ? res.status(200).json({ message: refresh })
      : res
          .status(403)
          .json({ message: "Have a error in process revoke refresh token" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
}
async function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(403).json({ message: "Email or password invalid" });
  }

  try {
    const token = await firebaseService.Login(email, password);
    console.log(token);
    return token === "Password invalid"
      ? res.status(403).json({ message: token })
      : res.status(200).json({ message: "access token custom", token });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

async function createSessionLogin(req, res) {
  const idToken = req.body.idToken;
  // const csrfToken = req.body.csrfToken;

  // if (csrfToken !== req.cookies.csrfToken) {
  //   res.status(401).send("UNAUTHORIZED REQUEST !");
  // }
  try {
    const { sessionCookie, options } = await firebaseService.createSessionLogin(
      idToken
    );
    console.log("session Cookie", sessionCookie);
    res.end(JSON.stringify({ status: "success", cookies: options }));
  } catch (error) {
    res.status(401).send("UNAUTHORIZED REQUEST");
    console.log(error);
  }
}

async function BlockUser(req, res) {
  const { email } = req.body;
  try {
    const result = await firebaseService.BlockUser(email);
    return result
      ? res.status(200).json({ message: "User is block in 30 minutes" })
      : res.status(403).json({ message: "Have a error" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
}

module.exports = {
  signup,
  login,
  loginWithEmail,
  getInforByEmail,
  createToken,
  LoginwithCustomToken,
  checkVerifyToken,
  verifyTokenId,
  createSessionLogin,
  revokeRefreshToken,
  createJWT,
  resetPassword,
  BlockUser,
};
