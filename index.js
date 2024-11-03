require('dotenv').config();
const port = process.env.PORT || 4000;
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const { parse, compareAsc } = require("date-fns");

app.use(express.json());
app.use(cors());

// Database Connection with MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(error => console.error("MongoDB connection error:", error));


// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "default_secret";

// API Creation
app.get("/", (req, res) => {
    res.send("Express App is running");
});

// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Endpoint for image upload using Cloudinary
app.post("/upload", upload.single("product"), async (req, res) => {
    try {
        const streamUpload = (req) => {
            return new Promise((resolve, reject) => {
                const stream = cloudinary.uploader.upload_stream((error, result) => {
                    if (result) resolve(result);
                    else reject(error);
                });
                stream.end(req.file.buffer);
            });
        };
        const result = await streamUpload(req);
        res.json({
            success: true,
            image_url: result.secure_url, // Cloudinary URL
        });
    } catch (error) {
        res.status(500).json({ success: false, message: "Image upload failed", error });
    }
});

// Schema for Creating Products
const Product = mongoose.model("Product", {
    id: { type: Number, required: true },
    name: { type: String, required: true },
    image: { type: String, required: true }, // Cloudinary URL will be saved here
    description: { type: String, required: true },
    date: { type: Date, default: Date.now },
});

app.post("/addproduct", async (req, res) => {
    let products = await Product.find({});
    let id = products.length > 0 ? products[products.length - 1].id + 1 : 1;

    const product = new Product({
        id: id,
        name: req.body.name,
        image: req.body.image,
        description: req.body.description,
    });

    await product.save();
    res.json({ success: true, name: req.body.name });
});

// Delete Product
app.post("/removeproduct", async (req, res) => {
    await Product.findOneAndDelete({ id: req.body.id });
    res.json({ success: true, name: req.body.name });
});

// Get All Products
app.get("/allproducts", async (req, res) => {
    let products = await Product.find({});
    res.send(products);
});

// User Schema
const Users = mongoose.model("Users", {
    name: { type: String, required: true },
    email: { type: String, unique: true },
    phone: { type: String, unique: true },
    username: { type: String, unique: true },
    password: { type: String },
    date: { type: Date, default: Date.now },
    first: { type: Boolean, default: false },
    treatments: {
        oilySweetItchingDandruff: { type: Boolean, default: false },
        scalpPainWhenTouched: { type: Boolean, default: false },
        drynessTensionPain: { type: Boolean, default: false },
        flakingScalp: { type: Boolean, default: false },
        hairLossAmount: { type: String, default: "" },
        hairPillowLoss: { type: String, default: "" },
        shampooFrequency: { type: String, default: "" },
        preBathProduct: { type: String, default: "" },
        hotWaterUsage: { type: Boolean, default: false },
        coldWaterUsage: { type: Boolean, default: false },
        stress: { type: String, default: "" },
        meals: { type: String, default: "" },
        waterIntake: { type: String, default: "" },
        snacks: { type: String, default: "" },
        bloodTests: { type: String, default: "" },
        sleepIssues: { type: String, default: "" },
    },
    treatmentInfo: { type: String, default: "" },
    productInfo: { type: String, default: "" },
    treatmentType: { type: String, default: "Diagnosis" },
});

// Register User
app.post("/signup", async (req, res) => {
    try {
        // Check for existing user
        let checkEmail = await Users.findOne({ email: req.body.email });
        if (checkEmail) {
            return res.status(400).json({ success: false, errors: "Existing user found with same email address" });
        }
        
        let checkPhone = await Users.findOne({ phone: req.body.phone });
        if (checkPhone) {
            return res.status(400).json({ success: false, errors: "Existing user found with same phone number" });
        }
        
        let checkUsername = await Users.findOne({ username: req.body.username });
        if (checkUsername) {
            return res.status(400).json({ success: false, errors: "Existing user found with same username" });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        const user = new Users({
            name: req.body.name,
            email: req.body.email,
            phone: req.body.phone,
            username: req.body.username,
            password: hashedPassword,
        });

        await user.save();

        const data = { user: { id: user.id } };
        const token = jwt.sign(data, JWT_SECRET);
        res.json({ success: true, token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

// User login
app.post("/login", async (req, res) => {
    try {
        const userInput = req.body.userinput;
        const user = await Users.findOne({
            $or: [{ email: userInput }, { username: userInput }]
        });

        if (!user) {
            return res.json({ success: false, errors: "Wrong Email or Username" });
        }

        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
        if (!isPasswordCorrect) {
            return res.json({ success: false, errors: "Wrong Password" });
        }

        const data = { user: { id: user.id } };
        const token = jwt.sign(data, JWT_SECRET, { expiresIn: "1h" });
        res.json({ success: true, token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, errors: "Internal Server Error" });
    }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ success: false, errors: "Access denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(400).json({ success: false, errors: "Invalid token." });
    }
};

// Get user info
app.get("/getuserinfo", authenticateToken, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id).select("-password");
        if (!user) {
            return res.status(404).json({ success: false, errors: "User not found." });
        }
        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

app.post('/book-treatment', async (req, res) => {
    try {
        const { name, username, treatment, day, time } = req.body;

        // Find the date entry by day
        let dateEntry = await Dates.findOne({ day: day });
        if (!dateEntry) {
            return res.status(404).json({ success: false, errors: "Date entry not found." });
        }

        await Users.findOneAndUpdate(
            { username: username },
            { $set: { treatmentType: "Treatment" } },
            { new: true }
        );

        // Find the specific time slot and update booking
        const updatedTimes = dateEntry.times.map((slot) => {
            if (slot.time === time) {
                slot.booking = `${name} (${username}) - ${treatment}`;
            }
            return slot;
        });

        dateEntry.times = updatedTimes;

        // Save the updated date entry
        await dateEntry.save();

        res.json({ success: true, message: "Booking updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});


pp.post('/getuserinfoadmin', async (req, res) => {
    try {
        const userInput = req.body.userinput;
        const user = await Users.findOne({
            $or: [
                { email: userInput },
                { username: userInput },
                { phone: userInput}
            ]
        });
        if (!user) {
            return res.status(404).json({ success: false, errors: "User not found." });
        }
        res.json({ success: true, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

// Creating Endpoint for updating treatments and information
app.post('/updateuserinfo', async (req, res) => {
    try {
        const username = req.body.username;
        const updatedTreatments = req.body.treatments;
        const updatedTreatmentInfo = req.body.treatmentInfo;
        const updatedProductInfo = req.body.productInfo;
        console.log(req.body);

        // Find user by username and update treatments and information
        await Users.findOneAndUpdate(
            { username: username },
            { $set: { treatments: updatedTreatments, treatmentInfo: updatedTreatmentInfo, productInfo: updatedProductInfo, first: true } },
            { new: true }
        );

        res.json({ success: true, message: "User updated successfully." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

// Dates Schema
const Dates = mongoose.model("Dates", {
    day: { type: String, unique: true, required: true },
    times: [
        {
            time: { type: String, required: true },
            booking: { type: String, required: true },
        }
    ],
});

// Create Date
app.post("/create-date", async (req, res) => {
    try {
        let checkDate = await Dates.findOne({ day: req.body.day });
        if (checkDate) {
            return res.status(400).json({ success: false, errors: "A date entry already exists for this day" });
        }

        const dateEntry = new Dates({
            day: req.body.day,
            times: []
        });

        await dateEntry.save();

        res.json({ success: true, date: dateEntry, message: "Date added successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

// Add Timeslot
app.post("/add-timeslot", async (req, res) => {
    try {
        const { day, time, booking } = req.body;

        let dateEntry = await Dates.findOne({ day: day });
        if (!dateEntry) {
            return res.status(404).json({ success: false, errors: "Date entry not found." });
        }

        const existingTime = dateEntry.times.find(t => t.time === time);
        if (existingTime) {
            return res.status(400).json({ success: false, errors: "This timeslot already exists." });
        }

        dateEntry.times.push({ time, booking });

        dateEntry.times.sort((a, b) => {
            const timeAStart = parse(a.time.split('-')[0].trim(), 'h:mma', new Date());
            const timeBStart = parse(b.time.split('-')[0].trim(), 'h:mma', new Date());
            return compareAsc(timeAStart, timeBStart);
        });

        await dateEntry.save();

        res.json({ success: true, date: dateEntry, message: "Time added Successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

// Get Date
app.post("/get-date", async (req, res) => {
    try {
        const { day } = req.body;

        const dateEntry = await Dates.findOne({ day: day });
        if (!dateEntry) {
            return res.json({ success: true, date: { day: day, times: "Date not found" } });
        }

        res.json({ success: true, date: dateEntry });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, errors: "Server error" });
    }
});

app.listen(port, (error) => {
    if (!error) {
        console.log("Server Running on Port " + port);
    } else {
        console.log("Error : " + error);
    }
});
