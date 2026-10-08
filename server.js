require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const Product = require("./product");
const Business = require("./business");

const app = express();
const PORT = process.env.PORT || 5000;

mongoose.set("bufferCommands", false);

app.use(express.json({ limit: "5mb" }));
app.use(cors());

// Keep the legacy frontend product/business routes working for the prototype UI.
// The newer protected business-auth routes remain available for authenticated flows.

//* GRROX CUSTOMER LOGIN - *// 
const cryptoLib = require("crypto");
const jwtLib = require("jsonwebtoken");
const customerRouter = express.Router();

/* ================= MODELS ================= */

const customerSchema = new mongoose.Schema(
    {
        mobile: { type: String, required: true, unique: true },
        name: { type: String, trim: true, default: "" },
        email: { type: String, trim: true, lowercase: true, default: "" },
        city: { type: String, trim: true, default: "Jaipur" },
        area: { type: String, trim: true, default: "" },
        pincode: { type: String, trim: true, default: "" },
        address: { type: String, trim: true, default: "" },
        profileComplete: { type: Boolean, default: false },
        grroxId: {
            type: String,
            unique: true,
            sparse: true
        },
        lastLoginAt: { type: Date }
    },
    { timestamps: true }
);
const Customer = mongoose.models.Customer || mongoose.model("Customer", customerSchema);
async function generateGrroxCustomerId() {
    let id;
    let exists = true;

    while (exists) {
        id = String(
            Math.floor(10000000 + Math.random() * 90000000)
        );

        exists = await Customer.exists({ grroxId: id });
    }

    return id;
}

const otpSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true },
    otpHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    lastSentAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // expired OTP auto-delete
const Otp = mongoose.models.Otp || mongoose.model("Otp", otpSchema);

/* ================= OTP SERVICE ================= */
/* Real OTP lagane ke liye SIRF yahi section badalna hai. */

const OTP_MODE = process.env.OTP_MODE || "dev"; // "dev" | "live"
const DEV_OTP = "123456";
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const MAX_ATTEMPTS = 5;

function generateOtp() {
    return OTP_MODE === "dev" ? DEV_OTP : String(cryptoLib.randomInt(100000, 1000000));
}

// >>> YAHAN real SMS provider lagana hai (MSG91 / Fast2SMS / Twilio) <<<
async function deliverOtp(mobile, otp) {
    if (OTP_MODE === "dev") {
        console.log(`[DEV OTP] ${mobile} -> ${otp}`);
        return;
    }
    // Example: await msg91.send({ mobile: "91" + mobile, otp });
    throw new Error("SMS provider abhi configure nahi hai.");
}

const hashOtp = (mobile, otp) =>
    cryptoLib.createHash("sha256").update(`${mobile}:${otp}:${process.env.JWT_SECRET}`).digest("hex");

class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

async function sendOtp(mobile) {
    const existing = await Otp.findOne({ mobile });
    if (existing && Date.now() - existing.lastSentAt.getTime() < RESEND_COOLDOWN_MS) {
        throw new HttpError(429, "Thodi der baad dobara OTP maango.");
    }
    const otp = generateOtp();
    await Otp.findOneAndUpdate(
        { mobile },
        { otpHash: hashOtp(mobile, otp), attempts: 0, lastSentAt: new Date(), expiresAt: new Date(Date.now() + OTP_EXPIRY_MS) },
        { upsert: true, new: true }
    );
    await deliverOtp(mobile, otp);
}

async function verifyOtp(mobile, otp) {
    const record = await Otp.findOne({ mobile });
    if (!record || record.expiresAt < new Date()) throw new HttpError(400, "OTP expire ho gaya. Naya OTP maango.");
    if (record.attempts >= MAX_ATTEMPTS) throw new HttpError(429, "Bahut galat attempts. Naya OTP maango.");
    if (record.otpHash !== hashOtp(mobile, otp)) {
        record.attempts += 1;
        await record.save();
        throw new HttpError(400, "Galat OTP.");
    }
    await Otp.deleteOne({ mobile }); // OTP ek hi baar chalega
}

/* ================= JWT + MIDDLEWARE ================= */

const signToken = (customer) =>
    jwtLib.sign({ id: customer._id, role: "customer" }, process.env.JWT_SECRET, { expiresIn: "30d" });

async function requireCustomer(req, res, next) {
    try {
        const header = req.headers.authorization || "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : null;
        if (!token) throw new HttpError(401, "Login required.");
        const payload = jwtLib.verify(token, process.env.JWT_SECRET);
        if (payload.role !== "customer") throw new HttpError(403, "Not allowed.");
        const customer = await Customer.findById(payload.id);
        if (!customer) throw new HttpError(401, "Account nahi mila.");
        req.customer = customer;
        next();
    } catch (err) {
        res.status(err.status || 401).json({ message: err.status ? err.message : "Session expire ho gaya. Dobara login karo." });
    }
}

/* ================= ROUTES ================= */

const isMobile = (v) => /^[6-9]\d{9}$/.test(String(v || ""));
const handle = (fn) => async (req, res) => {
    try { await fn(req, res); }
    catch (err) {
        if (!err.status) console.error("Customer auth error:", err);
        res.status(err.status || 500).json({ message: err.status ? err.message : "Server error." });
    }
};
const publicCustomer = (c) => ({
    id: c._id,
    grroxId: c.grroxId,
    mobile: c.mobile,
    name: c.name,
    email: c.email,
    city: c.city,
    area: c.area,
    pincode: c.pincode,
    address: c.address,
    profileComplete: c.profileComplete
});

// 1) OTP bhejo
customerRouter.post("/send-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    if (!isMobile(mobile)) throw new HttpError(400, "Valid 10-digit mobile number daalo.");
    await sendOtp(mobile);
    res.json({ message: "OTP bhej diya gaya.", devMode: OTP_MODE === "dev" });
}));

// 2) OTP verify -> login (naya customer ho to account ban jata hai)
customerRouter.post("/verify-otp", handle(async (req, res) => {
    const mobile = String(req.body.mobile || "").trim();
    const otp = String(req.body.otp || "").trim();
    if (!isMobile(mobile) || !/^\d{6}$/.test(otp)) throw new HttpError(400, "Mobile ya OTP galat hai.");
    await verifyOtp(mobile, otp);

    let customer = await Customer.findOne({ mobile });
    const isNewUser = !customer;

    if (!customer) {
        customer = new Customer({
            mobile,
            grroxId: await generateGrroxCustomerId()
        });
    }

    customer.lastLoginAt = new Date();
    await customer.save();

    res.json({
        message: "Login successful.",
        token: signToken(customer),
        isNewUser,
        needsProfile: !customer.profileComplete,
        customer: publicCustomer(customer)
    });
}));

// 3) Apni profile dekho (session check)
customerRouter.get("/me", requireCustomer, handle(async (req, res) => {
    res.json({ customer: publicCustomer(req.customer) });
}));

// 4) Profile save / update
customerRouter.put("/me", requireCustomer, handle(async (req, res) => {
    const name = String(req.body.name || "").trim().slice(0, 60);
    const email = String(req.body.email || "").trim().slice(0, 100);
    const city = String(req.body.city || "").trim().slice(0, 50);
    const area = String(req.body.area || "").trim().slice(0, 60);
    const pincode = String(req.body.pincode || "").trim();
    const address = String(req.body.address || "").trim().slice(0, 250);

    if (name.length < 2) throw new HttpError(400, "Apna naam daalo.");
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Valid email daalo.");
    if (pincode && !/^\d{6}$/.test(pincode)) {
        throw new HttpError(400, "Pincode 6 digit ka hona chahiye.");
    }

    validateJaipurLocation(
        city || "Jaipur",
        area,
        pincode
    );

    Object.assign(req.customer, {
        name,
        email,
        city: "Jaipur",
        area,
        pincode,
        address,
        profileComplete: true
    });
    await req.customer.save();
    res.json({ message: "Profile saved.", customer: publicCustomer(req.customer) });
}));

// Routes ko server se jodo
app.use("/api/customers", customerRouter);
/* ===================== CUSTOMER LOGIN END ===================== */

/* ======================================================================
   GRROX BUSINESS LOGIN (OTP + JWT) + SECURE SHOP / DEALS */
const BUSINESS_MODEL = "Business";
const PRODUCT_MODEL = "Product";
const DEAL_CATEGORIES = ["Electronics", "Clothing", "Grocery", "Stationery", "Electrical", "Food", "Salon", "Furniture", "Other"];
const bizRouter = express.Router();

const getModel = (name) => {
    const m = mongoose.models[name];
    if (!m) throw new HttpError(500, `"${name}" model nahi mila. server.js me apne model ka naam dekho aur BUSINESS_MODEL / PRODUCT_MODEL badlo.`);
    return m;
};
const bizStr = (v, max) => String(v == null ? "" : v).trim().slice(0, max);
const isBizMobile = (v) => /^\d{10}$/.test(String(v || ""));
const signBizToken = (b) => jwtLib.sign({ id: b._id, role: "business" }, process.env.JWT_SECRET, { expiresIn: "30d" });
const bizPub = (b) => ({
    _id: b._id, businessName: b.businessName, ownerName: b.ownerName, mobile: b.mobile,
    category: b.category, address: b.address, city: b.city, area: b.area,
    pincode: b.pincode, shopStatus: b.shopStatus || "Open"
});
const bearer = (req) => {
    const h = req.headers.authorization || "";
    return h.startsWith("Bearer ") ? h.slice(7) : null;
};

/* ---------- Middleware: sirf login business andar aa sakta hai ---------- */
async function requireBusiness(req, res, next) {
    try {
        const token = bearer(req);
        if (!token) throw new HttpError(401, "Login required.");
        const payload = jwtLib.verify(token, process.env.JWT_SECRET);
        if (payload.role !== "business") throw new HttpError(403, "Not allowed.");
        const business = await getModel(BUSINESS_MODEL).findById(payload.id);
        if (!business) throw new HttpError(401, "Business account nahi mila.");
        req.business = business;
        next();
    } catch (err) {
        res.status(err.status || 401).json({ message: err.status ? err.message : "Session expire ho gaya. Dobara login karo." });
    }
}

/* ---------- Validation ---------- */
const SHOP_FIELDS = { businessName: [2, 80], ownerName: [2, 60], category: [1, 40], address: [5, 250], city: [2, 50], area: [2, 60] };
/* ================= JAIPUR LOCATION VALIDATION ================= */

const JAIPUR_PINCODES = new Set([
    "302001",
    "302002",
    "302003",
    "302004",
    "302005",
    "302006",
    "302012",
    "302013",
    "302015",
    "302016",
    "302017",
    "302018",
    "302019",
    "302020",
    "302021",
    "302022",
    "302025",
    "302026",
    "302027",
    "302028",
    "302029",
    "302031",
    "302033",
    "302034",
    "302036",
    "302037",
    "302039"
]);

function validateJaipurLocation(city, area, pincode) {
    const cleanCity = String(city || "").trim().toLowerCase();
    const cleanArea = String(area || "").trim();
    const cleanPincode = String(pincode || "").trim();

    if (cleanCity !== "jaipur") {
        throw new HttpError(
            400,
            "GRROX abhi sirf Jaipur me available hai."
        );
    }

    if (!JAIPUR_PINCODES.has(cleanPincode)) {
        throw new HttpError(
            400,
            "Ye Jaipur ka valid PIN code nahi hai."
        );
    }

    if (cleanArea.length < 2) {
        throw new HttpError(
            400,
            "Jaipur ka valid area daalo."
        );
    }

    return true;
}
function cleanShop(b, partial) {
    const out = {};
    for (const [k, [min, max]] of Object.entries(SHOP_FIELDS)) {
        if (partial && b[k] === undefined) continue;
        const v = bizStr(b[k], max);
        if (v.length < min) throw new HttpError(400, `${k} sahi se bharo.`);
        out[k] = v;
    }
    if (!partial || b.pincode !== undefined) {
        const p = bizStr(b.pincode, 6);

        if (!/^\d{6}$/.test(p)) {
            throw new HttpError(
                400,
                "Pincode 6 digit ka hona chahiye."
            );
        }

        out.pincode = p;
    }

    if (!partial || b.city !== undefined || b.area !== undefined || b.pincode !== undefined) {
        const checkCity = out.city || b.city || "";
        const checkArea = out.area || b.area || "";
        const checkPincode = out.pincode || b.pincode || "";

        validateJaipurLocation(
            checkCity,
            checkArea,
            checkPincode
        );

        out.city = "Jaipur";
    }
    if (b.shopStatus !== undefined) {
        if (!["Open", "Closed"].includes(b.shopStatus)) throw new HttpError(400, "Shop status galat hai.");
        out.shopStatus = b.shopStatus;
    }
    return out;
}

function cleanDeal(b, partial) {
    const out = {};
    const has = (k) => b[k] !== undefined;
    if (!partial || has("name")) {
        const v = bizStr(b.name, 100);
        if (v.length < 2) throw new HttpError(400, "Deal ka naam kam se kam 2 akshar ka ho.");
        out.name = v;
    }
    if (!partial || has("price")) {
        const v = Number(b.price);
        if (!(v > 0 && v <= 10000000)) throw new HttpError(400, "Deal price sahi daalo.");
        out.price = v;
    }
    if (!partial || has("originalPrice")) {
        const v = Number(b.originalPrice || 0);
        if (!(v >= 0 && v <= 10000000)) throw new HttpError(400, "MRP sahi daalo.");
        out.originalPrice = v;
    }
    if (!partial || has("category")) {
        const v = bizStr(b.category, 40);
        if (!DEAL_CATEGORIES.includes(v)) throw new HttpError(400, "Category list me se chuno.");
        out.category = v;
    }
    if (has("offer")) out.offer = bizStr(b.offer, 40);
    if (has("description")) out.description = bizStr(b.description, 500);
    if (has("image")) {

        const v = String(
            b.image == null ? "" : b.image
        ).trim();

        /* Empty image allowed */
        if (!v) {
            out.image = "";
        }

        /* Uploaded Base64 image */
        else if (
            /^data:image\/(jpeg|png|webp);base64,/i.test(v)
        ) {

            /* Approximate 4MB limit */
            if (v.length > 5.5 * 1024 * 1024) {
                throw new HttpError(
                    400,
                    "Image maximum 4MB ki honi chahiye."
                );
            }

            out.image = v;
        }

        /* Old image URL bhi support rahega */
        else if (/^https?:\/\//i.test(v)) {

            out.image = v;

        }

        else {

            throw new HttpError(
                400,
                "Invalid image format."
            );
        }
    }
    return out;
}

const checkPrices = (price, mrp) => {
    if (mrp > 0 && price > mrp) throw new HttpError(400, "Deal price MRP se zyada nahi ho sakti.");
};

/* ---------- AUTH ROUTES ---------- */

bizRouter.post("/send-otp", handle(async (req, res) => {
    const mobile = bizStr(req.body.mobile, 10);
    if (!isBizMobile(mobile)) throw new HttpError(400, "Valid 10-digit mobile number daalo.");
    await sendOtp(mobile);
    res.json({ message: "OTP bhej diya gaya.", devMode: OTP_MODE === "dev" });
}));

// OTP sahi + account hai -> login token. Account nahi hai -> signupToken (15 min)
bizRouter.post("/verify-otp", handle(async (req, res) => {
    const mobile = bizStr(req.body.mobile, 10);
    const otp = bizStr(req.body.otp, 6);
    if (!isBizMobile(mobile) || !/^\d{6}$/.test(otp)) throw new HttpError(400, "Mobile ya OTP galat hai.");
    await verifyOtp(mobile, otp);

    const business = await getModel(BUSINESS_MODEL).findOne({ mobile });
    if (business) {
        return res.json({ exists: true, token: signBizToken(business), business: bizPub(business) });
    }
    const signupToken = jwtLib.sign({ mobile, role: "business-signup" }, process.env.JWT_SECRET, { expiresIn: "15m" });
    res.json({ exists: false, signupToken });
}));

// Naya business: mobile body se nahi, verified signupToken se aata hai
bizRouter.post("/signup", handle(async (req, res) => {
    let payload;
    try { payload = jwtLib.verify(bearer(req) || "", process.env.JWT_SECRET); }
    catch (e) { throw new HttpError(401, "OTP verification expire ho gaya. Dobara OTP se verify karo."); }
    if (payload.role !== "business-signup") throw new HttpError(403, "Not allowed.");

    const Business = getModel(BUSINESS_MODEL);
    if (await Business.findOne({ mobile: payload.mobile })) throw new HttpError(409, "Is mobile number se account pehle se hai. Login karo.");

    const data = cleanShop(req.body, false);
    delete data.shopStatus;
    const business = await Business.create({ ...data, mobile: payload.mobile, shopStatus: "Open" });
    res.status(201).json({ token: signBizToken(business), business: bizPub(business) });
}));

/* ---------- MY SHOP (sirf apni shop) ---------- */

bizRouter.get("/me", requireBusiness, handle(async (req, res) => {
    res.json({ business: bizPub(req.business) });
}));

bizRouter.put("/me", requireBusiness, handle(async (req, res) => {
    const data = cleanShop(req.body, true); // mobile aur _id kabhi update nahi hote
    Object.assign(req.business, data);
    await req.business.save();
    if (data.businessName) {
        await getModel(PRODUCT_MODEL).updateMany({ businessId: String(req.business._id) }, { shopName: data.businessName });
    }
    res.json({ message: "Shop updated.", business: bizPub(req.business) });
}));

bizRouter.post("/me/toggle-status", requireBusiness, handle(async (req, res) => {
    req.business.shopStatus = req.business.shopStatus === "Closed" ? "Open" : "Closed";
    await req.business.save();
    res.json({ business: bizPub(req.business) });
}));

/* ---------- MY DEALS (ownership check har jagah) ---------- */

bizRouter.get("/deals", requireBusiness, handle(async (req, res) => {
    const products = await getModel(PRODUCT_MODEL).find({ businessId: String(req.business._id) }).sort({ _id: -1 });
    res.json({ products });
}));

bizRouter.post("/deals", requireBusiness, handle(async (req, res) => {
    const data = cleanDeal(req.body, false);
    checkPrices(data.price, data.originalPrice);
    const product = await getModel(PRODUCT_MODEL).create({
        ...data,
        shopName: req.business.businessName,      // client se nahi, server se
        businessId: String(req.business._id),     // token wale business se
        city: req.business.city || "Jaipur"
    });
    res.status(201).json({ message: "Deal added.", product });
}));

bizRouter.put("/deals/:id", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    const deal = await getModel(PRODUCT_MODEL).findOne({ _id: req.params.id, businessId: String(req.business._id) });
    if (!deal) throw new HttpError(404, "Deal nahi mili.");   // doosre ki deal bhi yahi jawab degi
    const data = cleanDeal(req.body, true);
    checkPrices(data.price ?? deal.price, data.originalPrice ?? deal.originalPrice);
    Object.assign(deal, data);
    await deal.save();
    res.json({ message: "Deal updated.", product: deal });
}));

bizRouter.delete("/deals/:id", requireBusiness, handle(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, "Deal nahi mili.");
    const r = await getModel(PRODUCT_MODEL).deleteOne({ _id: req.params.id, businessId: String(req.business._id) });
    if (!r.deletedCount) throw new HttpError(404, "Deal nahi mili.");
    res.json({ message: "Deal deleted." });
}));

app.use("/api/business-auth", bizRouter);
/* ===================== BUSINESS LOGIN END ===================== */

function requireDb(res) {
    if (mongoose.connection.readyState !== 1) {
        res.status(503).json({
            message: "Database unavailable. Please check your MongoDB connection."
        });
        return true;
    }
    return false;
}

// HOME
app.get("/", (req, res) => {
    res.json({
        message: "GRROX Backend is running!"
    });
});

// GET ALL PRODUCTS
app.get("/api/products", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const products = await Product.find().sort({ createdAt: -1 });

        res.json({
            message: "Products fetched successfully!",
            products: products
        });
    } catch (error) {
        res.status(500).json({
            message: "Products fetch failed",
            error: error.message
        });
    }
});

// ADD PRODUCT
app.post("/api/products", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const product = new Product(req.body);
        const savedProduct = await product.save();

        res.status(201).json({
            message: "Product saved successfully!",
            product: savedProduct
        });
    } catch (error) {
        res.status(400).json({
            message: "Product save failed",
            error: error.message
        });
    }
});

// UPDATE PRODUCT
app.put("/api/products/:id", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const updatedProduct = await Product.findByIdAndUpdate(
            req.params.id,
            req.body,
            {
                new: true,
                runValidators: true
            }
        );

        if (!updatedProduct) {
            return res.status(404).json({
                message: "Product not found"
            });
        }

        res.json({
            message: "Product updated successfully!",
            product: updatedProduct
        });
    } catch (error) {
        res.status(400).json({
            message: "Product update failed",
            error: error.message
        });
    }
});

// DELETE PRODUCT
app.delete("/api/products/:id", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const deletedProduct = await Product.findByIdAndDelete(req.params.id);

        if (!deletedProduct) {
            return res.status(404).json({
                message: "Product not found"
            });
        }

        res.json({
            message: "Product deleted successfully!",
            product: deletedProduct
        });
    } catch (error) {
        res.status(400).json({
            message: "Product delete failed",
            error: error.message
        });
    }
});

// CREATE BUSINESS ACCOUNT
app.post("/api/businesses", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const {
            ownerName,
            mobile,
            businessName,
            category,
            address,
            city,
            area,
            pincode
        } = req.body;

        const existingBusiness = await Business.findOne({ mobile });

        if (existingBusiness) {
            return res.status(409).json({
                message: "Business account already exists with this mobile number."
            });
        }

        const business = new Business({
            ownerName,
            mobile,
            businessName,
            category,
            address,
            city,
            area,
            pincode
        });

        const savedBusiness = await business.save();

        res.status(201).json({
            message: "Business account created successfully!",
            business: savedBusiness
        });
    } catch (error) {
        res.status(400).json({
            message: "Business account creation failed",
            error: error.message
        });
    }
});

// GET BUSINESS BY ID
app.get("/api/businesses/:id", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const business = await Business.findById(req.params.id);

        if (!business) {
            return res.status(404).json({
                message: "Business not found"
            });
        }

        res.json({
            message: "Business fetched successfully!",
            business: business
        });
    } catch (error) {
        res.status(400).json({
            message: "Business fetch failed",
            error: error.message
        });
    }
});

// UPDATE BUSINESS
app.put("/api/businesses/:id", async (req, res) => {
    if (requireDb(res)) return;

    try {
        const {
            ownerName,
            mobile,
            businessName,
            category,
            address,
            city,
            area,
            pincode,
            shopStatus
        } = req.body;

        const updatedBusiness = await Business.findByIdAndUpdate(
            req.params.id,
            {
                ownerName,
                mobile,
                businessName,
                category,
                address,
                city,
                area,
                pincode,
                shopStatus
            },
            {
                new: true,
                runValidators: true
            }
        );

        if (!updatedBusiness) {
            return res.status(404).json({
                message: "Business not found"
            });
        }

        res.json({
            message: "Business updated successfully!",
            business: updatedBusiness
        });
    } catch (error) {
        res.status(400).json({
            message: "Business update failed",
            error: error.message
        });
    }
});

async function startServer() {
    if (!process.env.MONGODB_URI) {
        console.warn("MONGODB_URI is not defined in the environment. Starting server without MongoDB.");
        const PORT = process.env.PORT || 5000;

        app.listen(PORT, "0.0.0.0", () => {
            console.log(`GRROX Backend running on port ${PORT}`);
        });
        return;
    }


    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("MongoDB connected successfully!");
    } catch (error) {
        console.error("MongoDB connection failed:", error.message);
        console.warn("Continuing without MongoDB; database-dependent routes will return 503 until the DB is reachable.");
    }

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, "0.0.0.0", () => {
        console.log(`GRROX Backend running on port ${PORT}`);
    });
}

if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };