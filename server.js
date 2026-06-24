/* ============================================================
   DIGITAL MARKETING AGENCY — PRODUCTION BACKEND (single file)
   Stack: Node + Express + MongoDB + JWT + RBAC + Cloudinary
   ============================================================ */

require("dotenv").config();
const express        = require("express");
const mongoose       = require("mongoose");
const bcrypt         = require("bcryptjs");
const jwt            = require("jsonwebtoken");
const cookieParser   = require("cookie-parser");
const cors           = require("cors");
const helmet         = require("helmet");
const morgan         = require("morgan");
const rateLimit      = require("express-rate-limit");
const mongoSanitize  = require("express-mongo-sanitize");
const xss            = require("xss-clean");
const multer         = require("multer");
const nodemailer     = require("nodemailer");
const crypto         = require("crypto");
const path           = require("path");
const fs             = require("fs");
const { body, validationResult } = require("express-validator");
const cloudinary     = require("cloudinary").v2;

/* ============================================================
   1. APP INITIALIZATION
   ============================================================ */
const app = express();
const PORT = process.env.PORT || 5000;

/* ============================================================
   2. CLOUDINARY CONFIG
   ============================================================ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

/* ============================================================
   3. GLOBAL MIDDLEWARE — SECURITY + PARSERS
   ============================================================ */
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(morgan("dev"));

// Global rate limiter
app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, message: "Too many requests, try later." },
}));

// Stricter limiter for auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: "Too many auth attempts." },
});

/* ============================================================
   4. MULTER (file upload to temp /uploads)
   ============================================================ */
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename:    (_, file, cb) => cb(null, Date.now() + "-" + file.originalname),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (/jpeg|jpg|png|webp/.test(file.mimetype)) cb(null, true);
    else cb(new Error("Only image files allowed"));
  },
});

/* ============================================================
   5. MONGOOSE MODELS
   ============================================================ */

// ---- USER ----
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true },
  phone:        { type: String },
  password:     { type: String, required: true, minlength: 6, select: false },
  role:         { type: String, enum: ["admin", "employee", "client"], default: "client" },
  isVerified:   { type: Boolean, default: false },
  refreshToken: { type: String, select: false },
  profileImage: { type: String, default: "" },
  verifyToken:  String,
  resetToken:   String,
  resetExpires: Date,
  isDeleted:    { type: Boolean, default: false }, // soft delete
}, { timestamps: true });

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(entered, this.password);
};
const User = mongoose.model("User", userSchema);

// ---- CONTACT ----
const Contact = mongoose.model("Contact", new mongoose.Schema({
  name:    { type: String, required: true },
  email:   { type: String, required: true },
  phone:   String,
  company: String,
  service: String,
  message: { type: String, required: true },
  status:  { type: String, enum: ["new", "read", "responded"], default: "new" },
}, { timestamps: true }));

// ---- SERVICE ----
const Service = mongoose.model("Service", new mongoose.Schema({
  title:       { type: String, required: true },
  description: { type: String, required: true },
  image:       String,
  category:    String,
  price:       Number,
  isActive:    { type: Boolean, default: true },
}, { timestamps: true }));

// ---- LEAD ----
const Lead = mongoose.model("Lead", new mongoose.Schema({
  clientName: { type: String, required: true },
  email:      { type: String, required: true },
  phone:      String,
  source:     String,
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  status:     { type: String, enum: ["new", "contacted", "qualified", "converted", "lost"], default: "new" },
  notes:      String,
}, { timestamps: true }));

/* ============================================================
   6. HELPER UTILITIES
   ============================================================ */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const ok    = (res, data = {}, message = "Operation successful", code = 200) =>
  res.status(code).json({ success: true, message, data });
const fail  = (res, message = "Something went wrong", code = 400) =>
  res.status(code).json({ success: false, message });

const signAccess  = (id) => jwt.sign({ id }, process.env.JWT_ACCESS_SECRET,  { expiresIn: process.env.JWT_ACCESS_EXPIRES });
const signRefresh = (id) => jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES });

const cookieOpts = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge:   7 * 24 * 60 * 60 * 1000,
};

// Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({ from: process.env.FROM_EMAIL, to, subject, html });
  } catch (e) { console.error("Email error:", e.message); }
};

/* ============================================================
   7. MIDDLEWARES
   ============================================================ */

// Validation result handler
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return fail(res, errors.array()[0].msg, 422);
  next();
};

// Protect route — verify JWT
const protect = asyncHandler(async (req, res, next) => {
  let token = req.cookies?.accessToken;
  if (!token && req.headers.authorization?.startsWith("Bearer "))
    token = req.headers.authorization.split(" ")[1];
  if (!token) return fail(res, "Not authenticated", 401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.isDeleted) return fail(res, "User not found", 401);
    req.user = user;
    next();
  } catch {
    return fail(res, "Invalid or expired token", 401);
  }
});

// Role-based authorization
const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return fail(res, "Forbidden: insufficient role", 403);
  next();
};

/* ============================================================
   8. AUTH ROUTES   /api/auth
   ============================================================ */
const authRouter = express.Router();
authRouter.use(authLimiter);

// Signup
authRouter.post("/signup",
  [
    body("name").notEmpty().withMessage("Name required"),
    body("email").isEmail().withMessage("Valid email required"),
    body("password").isLength({ min: 6 }).withMessage("Password min 6 chars"),
  ],
  validate,
  asyncHandler(async (req, res) => {
    const { name, email, password, phone, role } = req.body;
    if (await User.findOne({ email })) return fail(res, "Email already registered", 409);

    const verifyToken = crypto.randomBytes(32).toString("hex");
    const user = await User.create({
      name, email, password, phone,
      role: role === "admin" ? "client" : (role || "client"), // never auto-grant admin
      verifyToken,
    });

    await sendEmail(email, "Verify your email",
      `<p>Hi ${name}, verify: <a href="${process.env.CLIENT_URL}/verify/${verifyToken}">Click here</a></p>`);

    ok(res, { id: user._id }, "Signup successful. Check email to verify.", 201);
  })
);

// Login
authRouter.post("/login",
  [body("email").isEmail(), body("password").notEmpty()],
  validate,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email, isDeleted: false }).select("+password");
    if (!user || !(await user.matchPassword(password)))
      return fail(res, "Invalid credentials", 401);

    const accessToken  = signAccess(user._id);
    const refreshToken = signRefresh(user._id);
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    res.cookie("accessToken",  accessToken,  { ...cookieOpts, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshToken", refreshToken, cookieOpts);

    ok(res, {
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      accessToken,
    }, "Login successful");
  })
);

// Logout
authRouter.post("/logout", protect, asyncHandler(async (req, res) => {
  req.user.refreshToken = null;
  await req.user.save({ validateBeforeSave: false });
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  ok(res, {}, "Logged out");
}));

// Refresh token
authRouter.post("/refresh-token", asyncHandler(async (req, res) => {
  const token = req.cookies?.refreshToken || req.body.refreshToken;
  if (!token) return fail(res, "No refresh token", 401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id).select("+refreshToken");
    if (!user || user.refreshToken !== token) return fail(res, "Invalid refresh token", 401);

    const accessToken = signAccess(user._id);
    res.cookie("accessToken", accessToken, { ...cookieOpts, maxAge: 15 * 60 * 1000 });
    ok(res, { accessToken }, "Token refreshed");
  } catch {
    return fail(res, "Invalid refresh token", 401);
  }
}));

// Forgot password
authRouter.post("/forgot-password",
  [body("email").isEmail()], validate,
  asyncHandler(async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return ok(res, {}, "If email exists, reset link sent"); // do not leak

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetToken   = crypto.createHash("sha256").update(resetToken).digest("hex");
    user.resetExpires = Date.now() + 15 * 60 * 1000;
    await user.save({ validateBeforeSave: false });

    await sendEmail(user.email, "Password Reset",
      `<p>Reset link (valid 15 min): <a href="${process.env.CLIENT_URL}/reset-password/${resetToken}">Reset</a></p>`);

    ok(res, {}, "If email exists, reset link sent");
  })
);

// Reset password
authRouter.post("/reset-password",
  [body("token").notEmpty(), body("password").isLength({ min: 6 })], validate,
  asyncHandler(async (req, res) => {
    const hashed = crypto.createHash("sha256").update(req.body.token).digest("hex");
    const user = await User.findOne({ resetToken: hashed, resetExpires: { $gt: Date.now() } });
    if (!user) return fail(res, "Invalid or expired token", 400);

    user.password = req.body.password;
    user.resetToken = undefined;
    user.resetExpires = undefined;
    await user.save();
    ok(res, {}, "Password reset successful");
  })
);

// Change password
authRouter.patch("/change-password",
  protect,
  [body("oldPassword").notEmpty(), body("newPassword").isLength({ min: 6 })], validate,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select("+password");
    if (!(await user.matchPassword(req.body.oldPassword))) return fail(res, "Old password incorrect", 401);
    user.password = req.body.newPassword;
    await user.save();
    ok(res, {}, "Password changed");
  })
);

// Profile
authRouter.get("/profile", protect, asyncHandler(async (req, res) => {
  ok(res, { user: req.user }, "Profile fetched");
}));

app.use("/api/auth", authRouter);

/* ============================================================
   9. USER ROUTES  /api/users  (Admin)
   ============================================================ */
const userRouter = express.Router();

userRouter.get("/", protect, authorize("admin"), asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search = "", role, sort = "-createdAt" } = req.query;
  const q = { isDeleted: false };
  if (search) q.$or = [{ name: new RegExp(search, "i") }, { email: new RegExp(search, "i") }];
  if (role) q.role = role;

  const users = await User.find(q).sort(sort).skip((page - 1) * limit).limit(+limit);
  const total = await User.countDocuments(q);
  ok(res, { users, total, page: +page, pages: Math.ceil(total / limit) });
}));

userRouter.get("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return fail(res, "User not found", 404);
  ok(res, { user });
}));

userRouter.put("/:id", protect, authorize("admin"),
  upload.single("profileImage"),
  asyncHandler(async (req, res) => {
    const updates = { ...req.body };
    delete updates.password;

    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "dma/users" });
      updates.profileImage = result.secure_url;
      fs.unlinkSync(req.file.path);
    }

    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
    ok(res, { user }, "User updated");
  })
);

userRouter.delete("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, { isDeleted: true }, { new: true });
  if (!user) return fail(res, "User not found", 404);
  ok(res, {}, "User deleted");
}));

app.use("/api/users", userRouter);

/* ============================================================
   10. CONTACT ROUTES  /api/contact
   ============================================================ */
const contactRouter = express.Router();

contactRouter.post("/",
  [body("name").notEmpty(), body("email").isEmail(), body("message").notEmpty()],
  validate,
  asyncHandler(async (req, res) => {
    const contact = await Contact.create(req.body);
    ok(res, { contact }, "Message submitted", 201);
  })
);

contactRouter.get("/", protect, authorize("admin"), asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, status } = req.query;
  const q = {};
  if (status) q.status = status;
  const contacts = await Contact.find(q).sort("-createdAt").skip((page - 1) * limit).limit(+limit);
  const total = await Contact.countDocuments(q);
  ok(res, { contacts, total });
}));

contactRouter.delete("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  await Contact.findByIdAndDelete(req.params.id);
  ok(res, {}, "Contact deleted");
}));

app.use("/api/contact", contactRouter);

/* ============================================================
   11. SERVICE ROUTES  /api/services
   ============================================================ */
const serviceRouter = express.Router();

serviceRouter.get("/", asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search = "", category, sort = "-createdAt" } = req.query;
  const q = { isActive: true };
  if (search) q.title = new RegExp(search, "i");
  if (category) q.category = category;
  const services = await Service.find(q).sort(sort).skip((page - 1) * limit).limit(+limit);
  const total = await Service.countDocuments(q);
  ok(res, { services, total });
}));

serviceRouter.post("/", protect, authorize("admin"),
  upload.single("image"),
  [body("title").notEmpty(), body("description").notEmpty()],
  validate,
  asyncHandler(async (req, res) => {
    const data = { ...req.body };
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "dma/services" });
      data.image = result.secure_url;
      fs.unlinkSync(req.file.path);
    }
    const service = await Service.create(data);
    ok(res, { service }, "Service created", 201);
  })
);

serviceRouter.put("/:id", protect, authorize("admin"),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const data = { ...req.body };
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, { folder: "dma/services" });
      data.image = result.secure_url;
      fs.unlinkSync(req.file.path);
    }
    const service = await Service.findByIdAndUpdate(req.params.id, data, { new: true });
    ok(res, { service }, "Service updated");
  })
);

serviceRouter.delete("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  await Service.findByIdAndDelete(req.params.id);
  ok(res, {}, "Service deleted");
}));

app.use("/api/services", serviceRouter);

/* ============================================================
   12. LEAD ROUTES  /api/leads
   ============================================================ */
const leadRouter = express.Router();

leadRouter.post("/", protect, authorize("admin"),
  [body("clientName").notEmpty(), body("email").isEmail()], validate,
  asyncHandler(async (req, res) => {
    const lead = await Lead.create(req.body);
    ok(res, { lead }, "Lead created", 201);
  })
);

leadRouter.get("/", protect, authorize("admin", "employee"), asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, status, search = "" } = req.query;
  const q = {};
  if (req.user.role === "employee") q.assignedTo = req.user._id;
  if (status) q.status = status;
  if (search) q.clientName = new RegExp(search, "i");

  const leads = await Lead.find(q).populate("assignedTo", "name email")
    .sort("-createdAt").skip((page - 1) * limit).limit(+limit);
  const total = await Lead.countDocuments(q);
  ok(res, { leads, total });
}));

leadRouter.put("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  const lead = await Lead.findByIdAndUpdate(req.params.id, req.body, { new: true });
  ok(res, { lead }, "Lead updated");
}));

leadRouter.patch("/:id/status", protect, authorize("admin", "employee"),
  asyncHandler(async (req, res) => {
    const lead = await Lead.findById(req.params.id);
    if (!lead) return fail(res, "Lead not found", 404);
    if (req.user.role === "employee" && String(lead.assignedTo) !== String(req.user._id))
      return fail(res, "Not your lead", 403);
    lead.status = req.body.status;
    await lead.save();
    ok(res, { lead }, "Status updated");
  })
);

leadRouter.delete("/:id", protect, authorize("admin"), asyncHandler(async (req, res) => {
  await Lead.findByIdAndDelete(req.params.id);
  ok(res, {}, "Lead deleted");
}));

app.use("/api/leads", leadRouter);

/* ============================================================
   13. ADMIN ANALYTICS  /api/admin/analytics
   ============================================================ */
app.get("/api/admin/analytics", protect, authorize("admin"), asyncHandler(async (_, res) => {
  const [users, employees, clients, services, contacts, leads, converted] = await Promise.all([
    User.countDocuments({ isDeleted: false }),
    User.countDocuments({ role: "employee", isDeleted: false }),
    User.countDocuments({ role: "client",   isDeleted: false }),
    Service.countDocuments({ isActive: true }),
    Contact.countDocuments(),
    Lead.countDocuments(),
    Lead.countDocuments({ status: "converted" }),
  ]);
  ok(res, { users, employees, clients, services, contacts, leads, converted });
}));

/* ============================================================
   14. HEALTH CHECK
   ============================================================ */
app.get("/", (_, res) => ok(res, { uptime: process.uptime() }, "DMA API live"));

/* ============================================================
   15. 404 + GLOBAL ERROR HANDLER
   ============================================================ */
app.use((req, res) => fail(res, `Route ${req.originalUrl} not found`, 404));

app.use((err, req, res, _next) => {
  console.error("❌", err);
  const code = err.statusCode || 500;
  res.status(code).json({
    success: false,
    message: err.message || "Internal server error",
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
});

/* ============================================================
   16. DATABASE + SERVER START
   ============================================================ */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });
