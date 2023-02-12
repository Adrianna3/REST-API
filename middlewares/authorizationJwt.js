const passport = require("passport");
const passportJWT = require("passport-jwt");
const service = require("../service/users.js");
require("dotenv").config();
const secret = process.env.SECRET;

const extractJWT = passportJWT.ExtractJwt;
const Strategy = passportJWT.Strategy;

const params = {
  secretOrKey: secret,
  jwtFromRequest: extractJWT.fromAuthHeaderAsBearerToken(),
};

passport.use(
  new Strategy(params, async (payload, done) => {
    try {
      const user = await service.getUserById(payload.id);
      if (!user) return done(new Error("User not found"));
      if (user) {
        return done(null, user);
      }
    } catch (err) {
      return done(err);
    }
  })
);

const auth = (req, res, next) => {
  passport.authenticate("jwt", { session: false }, (err, user) => {
    if (!req.headers.authorization)
      return res.status(401).json({ message: "Not authorized" });
    const token = req.headers.authorization.slice(7);
    if (token !== user.token || !user || err) {
      return res.status(401).json({ message: "Not authorized" });
    }
    req.user = user;
    next();
  })(req, res, next);
};

module.exports = { auth };
