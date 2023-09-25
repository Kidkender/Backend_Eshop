const express = require("express");
const authController = require("../controllers/authController");
const verifyAccessToken = require("../middlewares/verifyAccessToken");

const router = express.Router();

router.post("/signup", authController.signup);
router.get("/login", authController.login);
router.get("/loginEmail", authController.loginWithEmail);
router.get("/getInforUser", authController.getInforByEmail);
router.get("/checkToken", authController.checkVerifyToken);
router.get("/logincustomToken", authController.LoginwithCustomToken);
router.post("/resetPassword", authController.resetPassword);
router.get("/create-custom-token", authController.createToken);
router.post("/verifytokenid", authController.verifyTokenId);
router.get("/revokedrefreshToken", authController.revokeRefreshToken);
router.post("/createSessionLogin", authController.createSessionLogin);
router.get("/createjwt", authController.createJWT);
module.exports = router;
