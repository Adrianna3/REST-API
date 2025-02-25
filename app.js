const express = require("express");
const logger = require("morgan");
const cors = require("cors");
const path = require("path");

const contactsRouter = require("./routes/api/contacts");
const usersRouter = require("./routes/api/users");

const app = express();

const formatsLogger = app.get("env") === "development" ? "dev" : "short";

app.use(logger(formatsLogger));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  "/avatars",
  express.static(path.join(process.cwd(), "public", "avatars"))
);
app.use("/api/contacts", contactsRouter);
app.use("/api/users", usersRouter);

app.use((_, res) => {
  res.status(404).json({
    status: "error",
    code: 404,
    message: `That site doesn't exist`,
    data: "Not found",
  });
});

app.use((e, _, res) => {
  console.log(e.stack);
  res.status(500).json({
    status: "fail",
    code: 500,
    message: e.message,
    data: "Internal Server Error",
  });
});


module.exports = app;

