const admin = require("firebase-admin");
const serviceAccount = require("../secret/ecomerce-duck-acba153957d4.json");
const { private_key } = serviceAccount;
const { AppCheck } = require("firebase-admin/app-check");
const { getAuth } = require("firebase-admin/auth");

const appAdmin = admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const getCheck = new AppCheck(appAdmin);
const authAdmin = getAuth(appAdmin);
module.exports = { appAdmin, getCheck, authAdmin, private_key };
