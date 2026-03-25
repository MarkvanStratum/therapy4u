//--------------------------------------------
//	SERVER.JS — THERAPIST AI CHAT EDITION
//--------------------------------------------

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();
import OpenAI from "openai";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import Stripe from "stripe";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";
import multer from "multer";
import { handleCreateIntent } from "./payments.js";


//--------------------------------------------
//	BASIC SETUP
//--------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || "supersecret";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

app.use(cors());

//--------------------------------------------
// STRIPE WEBHOOK (CRITICAL: MUST BE BEFORE express.json())
//--------------------------------------------

app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error("Webhook Signature Error:", err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    async function applyPlan(plan, email) {
        let expiresAt = null;
        let isLifetime = false;

        if (plan === 'god' || plan === 'all') { // Keeping plan IDs same to avoid breaking Stripe metadata
            const date = new Date();
            date.setDate(date.getDate() + 30);
            expiresAt = date;
            isLifetime = false;
        } else if (plan === 'lifetime') {
            expiresAt = null;
            isLifetime = true;
        }

        try {
            const result = await pool.query(
                "UPDATE users SET plan = $1, expires_at = $2, lifetime = $3, messages_sent = 0 WHERE LOWER(email) = LOWER($4)",
                [plan, expiresAt, isLifetime, email]
            );
            
            if (result.rowCount > 0) {
                console.log(`✅ SUCCESS: Plan ${plan} applied to ${email}`);
            } else {
                console.log(`⚠️ WARNING: No user found with email ${email} to upgrade.`);
            }
        } catch (err) {
            console.error("❌ DATABASE ERROR during plan update:", err);
        }
    }

    if (event.type === "payment_intent.succeeded") {
        const paymentIntent = event.data.object;
        const plan = paymentIntent.metadata?.plan;
        const email = paymentIntent.metadata?.email; 

        if (email) {
            const userCheck = await pool.query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [email]);
            if (userCheck.rows.length === 0) {
                const tempPassword = crypto.randomBytes(8).toString('hex');
                const hashed = await bcrypt.hash(tempPassword, 10);
                await pool.query(
                    "INSERT INTO users (email, password, plan, lifetime, messages_sent) VALUES ($1, $2, $3, $4, 0)",
                    [email.toLowerCase(), hashed, plan, plan === 'lifetime']
                );
            }
            await applyPlan(plan, email);
        }
    }

    if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const plan = session.metadata?.plan;
        const email = session.metadata?.email || session.customer_details?.email;
        if (email) {
            await applyPlan(plan, email);
        }
    }
    res.json({ received: true });
});

//--------------------------------------------
// MIDDLEWARE (AFTER WEBHOOK)
//--------------------------------------------

app.use(express.json());

app.post("/api/create-landing-payment", handleCreateIntent);
app.post("/api/create-au-payment-3595", handleCreateIntent);
app.post("/api/create-payment-2995", handleCreateIntent);

//--------------------------------------------
//	DATABASE
//--------------------------------------------

const { Pool } = pkg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
	try {
		await pool.query(`
			CREATE TABLE IF NOT EXISTS users (
				id SERIAL PRIMARY KEY,
				email TEXT UNIQUE NOT NULL,
				password TEXT NOT NULL,
				credits INT DEFAULT 10,
				lifetime BOOLEAN DEFAULT false,
				reset_token TEXT,
				reset_token_expires TIMESTAMP,
				plan TEXT DEFAULT 'free',
				expires_at TIMESTAMP,
				messages_sent INT DEFAULT 0
			);
		`);

		await pool.query(`
			CREATE TABLE IF NOT EXISTS messages (
				id SERIAL PRIMARY KEY,
				user_id INT REFERENCES users(id) ON DELETE CASCADE,
				character_id INT NOT NULL,
				from_user BOOLEAN NOT NULL,
				text TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT NOW()
			);
		`);
		console.log("✅ Database ready");
	} catch (err) {
		console.error("❌ DB Init error:", err);
	}
})();

//--------------------------------------------
//	THERAPIST PROFILES (REPLACED BIBLICAL)
//--------------------------------------------

export const therapistProfiles = [
	{ id: 1, name: "Dr. Aris", image: "/img/Aris.png", description: "Senior Psychoanalyst. Specializes in deep subconscious exploration, dream analysis, and uncovering childhood patterns. Speaks with a calm, clinical, and observant tone." },
	{ id: 2, name: "Dr. Sarah", image: "/img/Sarah.png", description: "Cognitive Behavioral Specialist. Focuses on identifying negative thought patterns and providing actionable coping strategies for anxiety and stress." },
	{ id: 3, name: "Dr. Marcus", image: "/img/Marcus.png", description: "Humanistic Therapist. Emphasizes empathy, unconditional positive regard, and self-actualization. Warm, encouraging, and focused on the present moment." },
	{ id: 4, name: "Dr. Elena", image: "/img/Elena.png", description: "Trauma-Informed Counselor. Gentle, patient, and highly focused on creating a safe environment for emotional processing and healing." },
	{ id: 5, name: "Dr. Julian", image: "/img/Julian.png", description: "Existential Therapist. Helps users find meaning in life's challenges, focusing on free will, responsibility, and the search for purpose." }
];

app.get("/api/profiles", (req, res) => {
	res.json(therapistProfiles);
});

//--------------------------------------------
//	AUTH HELPERS
//--------------------------------------------

function authenticateToken(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader?.split(" ")[1];
	if (!token) return res.sendStatus(401);

	jwt.verify(token, SECRET_KEY, (err, user) => {
		if (err) return res.sendStatus(403);
		req.user = user;
		next();
	});
}

//--------------------------------------------
//	REGISTER / LOGIN
//--------------------------------------------

app.post("/api/register", async (req, res) => {
	let { email, password } = req.body || {};
	if (!email || !password) return res.status(400).json({ error: "Email and password required" });
	email = email.trim().toLowerCase();
	try {
		const check = await pool.query("SELECT 1 FROM users WHERE email = $1", [email]);
		if (check.rows.length > 0) return res.status(400).json({ error: "User already exists" });
		const hashed = await bcrypt.hash(password, 10);
		await pool.query(`INSERT INTO users (email, password) VALUES ($1, $2)`, [email, hashed]);
		res.status(201).json({ ok: true, message: "Registered successfully" });
	} catch (err) {
		res.status(500).json({ error: "Server error" });
	}
});

app.post("/api/login", async (req, res) => {
	const { email, password } = req.body || {};
	try {
		const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
		if (result.rows.length === 0) return res.status(400).json({ error: "Invalid credentials" });
		const user = result.rows[0];
		const match = await bcrypt.compare(password, user.password);
		if (!match) return res.status(400).json({ error: "Invalid credentials" });
		const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "7d" });
		res.json({ token });
	} catch (err) {
		res.status(500).json({ error: "Server error" });
	}
});

app.post("/api/create-payment-intent", authenticateToken, async (req, res) => {
    try {
        const { plan } = req.body;
        const email = req.user.email;
        const userId = req.user.id;
        const amounts = { 'god': 2995, 'all': 3595, 'lifetime': 4995 };
        const amount = amounts[plan];
        if (!amount) return res.status(400).json({ error: "Please select a valid plan." });

        const paymentIntent = await stripe.paymentIntents.create({
            amount,
            currency: "usd",
            metadata: { plan, email, userId },
        });
        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (e) {
        res.status(500).json({ error: "Payment Error: " + e.message });
    }
});

//--------------------------------------------
//	CHAT LOGIC
//--------------------------------------------

const openai = new OpenAI({	
	baseURL: "https://openrouter.ai/api/v1",
	apiKey: process.env.OPENROUTER_API_KEY,
	defaultHeaders: { 'HTTP-Referer': 'https://www.speaktoheaven.com', 'X-Title': 'Speak to Heaven' }
});

app.post("/api/chat", authenticateToken, async (req, res) => {
	try {
		const { characterId, message } = req.body;
		if (!characterId || !message) return res.status(400).json({ error: "Missing character or message" });

		const character = therapistProfiles.find(c => c.id === Number(characterId));
		if (!character) return res.status(400).json({ error: "Invalid therapist" });

		const userResult = await pool.query("SELECT plan, lifetime, expires_at, messages_sent FROM users WHERE id = $1", [req.user.id]);
		const userData = userResult.rows[0];
		const isPaid = userData.lifetime || (userData.expires_at && new Date(userData.expires_at) > new Date());

		if (!isPaid && parseInt(userData.messages_sent) >= 3) {
			return res.status(403).json({ error: "LIMIT_REACHED", message: "Limit reached. Please choose an offering." });
		}

		await pool.query(`INSERT INTO messages (user_id, character_id, from_user, text) VALUES ($1, $2, true, $3)`, [req.user.id, characterId, message]);

		const history = await pool.query(`SELECT * FROM messages WHERE user_id = $1 AND character_id = $2 ORDER BY created_at ASC LIMIT 20`, [req.user.id, characterId]);
		const chatHistory = history.rows.map(m => ({ role: m.from_user ? "user" : "assistant", content: m.text }));

		// UPDATED PROMPT FOR PSYCHOANALYST BEHAVIOR
		const systemPrompt = `You are ${character.name}. ${character.description} 
		RULES: 
		1. Maintain a professional, empathetic, and clinical tone. 
		2. Use psychoanalytic techniques: ask open-ended questions, encourage the user to explore their feelings, and occasionally offer insights into their subconscious motivations.
		3. Never mention being an AI. 
		4. If a user expresses a crisis or self-harm, gently advise them to seek immediate professional in-person help.`;

		const aiResponse = await openai.chat.completions.create({	
			model: "openai/gpt-3.5-turbo",	
			messages: [{ role: "system", content: systemPrompt }, ...chatHistory, { role: "user", content: message }],
			temperature: 0.7, max_tokens: 500
		});

		const reply = aiResponse.choices?.[0]?.message?.content;
		if (reply) await pool.query(`INSERT INTO messages (user_id, character_id, from_user, text) VALUES ($1, $2, false, $3)`, [req.user.id, characterId, reply]);
		if (!isPaid) await pool.query("UPDATE users SET messages_sent = messages_sent + 1 WHERE id = $1", [req.user.id]);

		res.json({ reply: reply || "(No response)" });
	} catch (err) {
		console.error(err);
		res.status(500).json({ error: "Server Error" });
	}
});

app.get("/api/chat/history", async (req, res) => {
	try {
		const authHeader = req.headers.authorization;
		const token = authHeader && authHeader.split(" ")[1];
		if (!token) return res.status(401).json({ error: "No token" });
		const decoded = jwt.verify(token, SECRET_KEY);
		const { characterId } = req.query;
		const history = await pool.query("SELECT * FROM messages WHERE user_id = $1 AND character_id = $2 ORDER BY created_at ASC LIMIT 50", [decoded.id, characterId]);
		res.json(history.rows);
	} catch (err) {
		res.status(500).json({ error: "Failed to load history" });
	}
});

//--------------------------------------------
//	STATIC FILES & START
//--------------------------------------------

app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/img", express.static(path.resolve(__dirname, "public/img")));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => { res.send(`<!DOCTYPE html><html><head><title>Therapy AI</title></head><body><h1>Speak To Serenity</h1></body></html>`); });

app.listen(PORT, () => {
	console.log(`🌍 Server running on Port: ${PORT}`);
});