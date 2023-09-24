const {
  signInWithCustomToken,
  signInWithEmailAndPassword,
} = require("firebase/auth");
const jwt = require("jsonwebtoken");
const { auth, getCheck } = require("./../firebase/config");

const admin = require("firebase-admin");
const serviceAccount = require("../secret/ecomerce-duck-acba153957d4.json");
const { private_key } = serviceAccount;
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

async function createUser(email, password) {
  const userRecord = await admin
    .auth()
    .createUser({ email: email, password: password });
  return userRecord;
}
function checkPassword(pass) {
  if (pass == "123123") {
    return true;
  }
  return false;
}

async function checkVerity(token) {
  try {
    const valid = await admin.appCheck().verifyToken(token);
    return valid;
  } catch (error) {
    console.error(error.message);
  }
}

async function verifyAccessToken(token) {
  try {
    const accessToken = await admin.auth().verifyAccessToken(body);
    return accessToken;
  } catch (error) {
    console.error(error.message);
  }
}

async function loginWithEmail(email, password) {
  const expirationTime = Math.floor(Date.now() / 1000) + 15 * 60;
  try {
    const inforUser = await getUserByEmail(email);
    const { uid } = inforUser;

    if (uid && checkPassword(password)) {
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
        // const infoUser = { uid, refreshToken, displayName, email };
        const newToken = await createJWT(uid);
        // console.log(newToken);
        return { ...user, newToken };
      })
      .catch((error) => {
        console.error(error.message);
      });
    return userCredentials;
  } catch (error) {
    console.error(error.message);
  }
}

async function getUserByEmail(email) {
  try {
    const inforUser = await admin.auth().getUserByEmail(email);
    // console.log(inforUser.passwordHash);
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
  try {
    const validRefresh = await admin
      .auth()
      .revokeRefreshTokens(uid)
      .then(() => {
        return admin.auth().getUser(uid);
      })
      .then((userRecord) => {
        return new Date(userRecord.tokensValidAfterTime).getTime() / 1000;
      })
      .then((timestamp) => {
        console.log(`Token revoked at ${timestamp}`);
      })
      .catch((error) => {
        console.error(error.message);
      });
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
  const customToken = await admin
    .auth()
    .createCustomToken(uid, { expiresIn: expiresIn });
  return customToken;
}

async function createSessionLogin(accessToken) {
  const expiresIn = 60 * 60 * 24 * 1000;

  try {
    const newSession = await admin
      .auth()
      .createSessionCookie(accessToken, { expiresIn })
      .then((sessionCokkie) => {
        const options = { maxAge: expiresIn, httpOnly: true, secure: true };
        return options;
      });
    return newSession;
  } catch (error) {
    console.error(error.message);
  }
}

module.exports = {
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
};
