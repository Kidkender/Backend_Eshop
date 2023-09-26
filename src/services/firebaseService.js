const {
  signInWithCustomToken,
  signInWithEmailAndPassword,
  sendPasswordResetEmail,
} = require("firebase/auth");
const { auth } = require("../firebase/config");
const { appAdmin, private_key, authAdmin } = require("../firebase/adminConfig");
const jwt = require("jsonwebtoken");
const { app } = require("firebase-admin");

async function createUser(email, password) {
  const userRecord = await appAdmin
    .auth()
    .createUser({ email: email, password: password });
  return userRecord;
}

async function checkVerity(token) {
  try {
    const valid = await appAdmin.appCheck().verifyToken(token);
    return valid;
  } catch (error) {
    console.error(error.message);
  }
}

async function verifyAccessToken(token) {
  try {
    const accessToken = await appAdmin.auth().verifyIdToken(token);
    return accessToken;
  } catch (error) {
    console.error(error.message);
  }
}

async function loginWithEmail(email) {
  const expirationTime = Math.floor(Date.now() / 1000) + 15 * 60;
  try {
    const inforUser = await getUserByEmail(email);
    console.log(inforUser);
    const { uid } = inforUser;
    if (uid) {
      const customToken = await createCustomToken(uid, { exp: expirationTime });
      return customToken;
    }
  } catch (error) {
    console.error(error.message);
  }
}

const createJWT = async (uid) => {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const firebase_email_admin =
    "firebase-adminsdk-gqxx7@ecomerce-duck.iam.gserviceaccount.com";
  if (!uid) {
    return;
  }
  try {
    const payload = {
      aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
      // aud: "projects/ecomerce-duck",
      iat: currentTimestamp,
      exp: currentTimestamp + 15 * 60,
      iss: firebase_email_admin,
      sub: firebase_email_admin,
      uid: uid,
      claims: {
        expiresIn: {
          expiresIn: currentTimestamp + 15 * 60,
        },
      },
    };

    const privateKey = private_key;

    const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });
    return token;
  } catch (error) {
    console.error(error.message);
  }
};

async function Login(email, password) {
  try {
    const userCredentials = await signInWithEmailAndPassword(
      auth,
      email,
      password
    )
      .then((userCredential) => {
        const user = userCredential.user;
        return user;
      })
      .then(async (user) => {
        const { uid, refreshToken, displayName, email } = user;

        const token = await createJWT(uid);
        return { displayName, email, refreshToken, token };
      })
      .catch((error) => {
        console.log("Password invalid");
        console.error(error);
        return "Password invalid";
      });
    return userCredentials;
  } catch (error) {
    console.error(error);
  }
}

async function resetPasswd(email) {
  try {
    const result = await getUserByEmail(email);

    if (result) {
      sendPasswordResetEmail(auth, email);
      return result.email;
    }
    console.log("User not exist");
    return result;
  } catch (error) {
    console.error(error.message);
    return false;
  }
}

async function getUserByEmail(email) {
  try {
    const inforUser = await appAdmin.auth().getUserByEmail(email);
    console.log(inforUser);
    return inforUser;
  } catch (error) {
    console.error(error.message);
  }
}

async function loginCustomToken(customToken) {
  try {
    const userCredential = await signInWithCustomToken(auth, customToken);
    return userCredential;
  } catch (error) {
    console.error(error.message);
  }
}

async function revokedRefreshToken(uid) {
  let status = false;
  try {
    const validRefresh = await appAdmin
      .auth()
      .revokeRefreshTokens(uid)
      .then(() => {
        return appAdmin.auth().getUser(uid);
      })
      .then((userRecord) => {
        return new Date(userRecord.tokensValidAfterTime).getTime() / 1000;
      })
      .then((timestamp) => {
        console.log(`Token revoked at ${timestamp}`);
        return (status = true);
      })
      .catch((error) => {
        console.error(error.message);
      });
    console.log(status);
    return validRefresh;
  } catch (error) {
    console.error(error.message);
  }
}

const SaveIDToken = (uid) => {
  const metadataRef = getDatabase().ref("/metadata" + uid);
  metadataRef.set({ revokeTime: utcRevocationTimeSecs }).then(() => {
    console.log("Database updated successfully");
  });
};

async function detectIdTokenRevoied(idToken) {
  let checkRevoked = true;
  try {
    await admin
      .auth()
      .verifyIdToken(idToken, checkRevoked)
      .then((payload) => {
        return true;
      })
      .catch((error) => {
        if (error.code == "auth/valid-token-revoked") {
          return false;
        }
      });
  } catch (error) {
    console.error(error.message);
    return;
  }
}

async function onIdTokenRevoke(email, password) {
  let credentials = await firebase.auth.EmailAuthProvider.credential(
    firebase.auth().currentUser.email,
    password
  );
  try {
    const newToken = auth.currentUser
      .reauthenticateWithCredential(credentials)
      .then((result) => {
        return result;
      });
    return newToken;
  } catch (error) {
    console.error(error.message);
  }
}

async function createCustomToken(uid, expiresIn) {
  try {
    const customToken = await appAdmin
      .auth()
      .createCustomToken(uid, { expiresIn: expiresIn });
    return customToken;
  } catch (error) {
    console.error(error.message);
  }
}

// appAdmin.auth().createSessionCookie();

async function createSessionLogin(idToken) {
  const expiresIn = 60 * 60 * 24 * 1000;

  const result = await appAdmin
    .auth()
    .createSessionCookie(idToken, { expiresIn: expiresIn })
    .then(async (sessionCookie) => {
      const options = { maxAge: sessionCookie, httpOnly: true, secure: true };
      console.log("session cookie created", sessionCookie);
      console.log("options", options);
      return { sessionCookie, options };
    });
  return result;
}

async function BlockUser(email) {
  const blockedUntil = Date.now() + 30 * 60 * 1000;
  try {
    const result = await appAdmin
      .auth()
      .getUserByEmail(email)
      .then((user) => {
        return user.uid;
      })
      .then(async (uid) => {
        await appAdmin
          .auth()
          .setCustomUserClaims(uid, { blocked: true })
          .then(() => {
            console.log("User blocked successfully");
            return true;
          })
          .catch((error) => {
            console.error("Error when block user", error);
            return false;
          });
      });
    return result;
  } catch (error) {
    console.log(error.message);
    return false;
  }
}

module.exports = {
  BlockUser,
  createUser,
  loginWithEmail,
  loginCustomToken,
  createCustomToken,
  getUserByEmail,
  checkVerity,
  verifyAccessToken,
  createSessionLogin,
  revokedRefreshToken,
  Login,
  onIdTokenRevoke,
  SaveIDToken,
  detectIdTokenRevoied,
  resetPasswd,
  createJWT,
};
