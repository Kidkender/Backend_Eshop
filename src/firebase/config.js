const { getAuth } = require("firebase/auth");
const { initializeApp } = require("firebase/app");
const { getAppCheck, AppCheck } = require("firebase-admin/app-check");
const { appCheck } = require("firebase-admin");
require("firebase/auth");

const firebaseConfig = {
  apiKey: "AIzaSyCKhM7NlwKPJ6zdDtWt1lWBtmYQGAGT7vM",
  authDomain: "ecomerce-duck.firebaseapp.com",
  projectId: "ecomerce-duck",
  storageBucket: "ecomerce-duck.appspot.com",
  messagingSenderId: "683145378767",
  appId: "1:683145378767:web:06c4346b46f1a37cc2b0ba",
  measurementId: "G-D95YNJWJWP",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const getCheck = new AppCheck(app);
module.exports = { app, auth, getCheck };
