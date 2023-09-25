const { getAuth } = require("firebase/auth");
const { initializeApp } = require("firebase/app");
const { getFirestore } = require("firebase/firestore");
const { getStorage } = require("firebase/storage");
const { getCheck } = require("firebase/app-check");
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

const db = getFirestore(app);
const storage = getStorage(app);

module.exports = { app, auth, getCheck };
