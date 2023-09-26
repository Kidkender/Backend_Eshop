const express = require("express");
const cors = require("cors");
var bodyParser = require("body-parser");

const authRoutes = require("./src/routes/authRoutes");

const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(express.json());

app.use("/auth", authRoutes);

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
