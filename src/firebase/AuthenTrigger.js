const functions = require("firebase-functions");
const { beforeUserSignIn } = require("firebase-functions/v2");

exports.unlockBlockedAccount = functions.auth.user().beforeSignIn((user) => {
  const blockedUntil = user.customClaims && user.customClaims.blockedUntil;
  if (blockedUntil && blockedUntil <= Date.now()) {
    return admin
      .auth()
      .setCustomUserClaims(user.uid, { blockedUntil: null })
      .then(() => {
        console.log("Unlock user successfully");
      })
      .catch((error) => {
        console.error("Error when unlock user:", error);
      });
  }
  return null;
});

export const beforeSignIn = beforeUserSignIn((event) => {
  return {
    sessionClaims: {
      signInIpAddress: event.signInIpAddress,
    },
  };
});
