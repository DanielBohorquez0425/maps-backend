import { Router } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../db.js";
import dotenv from "dotenv";

dotenv.config();
const router = Router();

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
    req.user = decoded;
    next();
  });
};

// Registro
router.post("/register", async (req, res) => {
  try {
    const { name, last_name, email, password } = req.body;

    if (!name || !last_name || !email || !password) {
      return res.status(400).json({ message: "Todos los campos son requeridos" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Formato de email inválido" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "La contraseña debe tener al menos 8 caracteres" });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "El usuario ya existe" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, last_name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id",
      [name, last_name, email, hashedPassword]
    );

    res.status(201).json({ 
      message: "Usuario registrado con éxito",
      userId: result.rows[0].id 
    });
  } catch (error) {
    console.error("Error en registro:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email y contraseña son requeridos" });
    }

    const userQuery = await pool.query(
      "SELECT id, name, last_name, email, password_hash FROM users WHERE email = $1",
      [email]
    );

    if (userQuery.rows.length === 0) {
      return res.status(400).json({ message: "Usuario no encontrado" });
    }

    const user = userQuery.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: "Credenciales incorrectas" });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        name: user.name,
        lastName: user.last_name
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ 
      token,
      user: {
        id: user.id,
        name: user.name,
        lastName: user.last_name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Verificar token
router.get("/verify", verifyToken, async (req, res) => {
  try {
    const userQuery = await pool.query(
      "SELECT id, name, last_name, email FROM users WHERE id = $1",
      [req.user.id]
    );

    if (userQuery.rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userQuery.rows[0];

    res.json({ 
      message: 'Token válido', 
      user: {
        id: user.id,
        name: user.name,
        lastName: user.last_name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Error verificando token:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Logout
router.post("/logout", verifyToken, (req, res) => {
  res.json({ message: "Logout exitoso" });
});

// Obtener perfil
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userQuery = await pool.query(
      "SELECT id, name, last_name, email, created_at FROM users WHERE id = $1",
      [req.user.id]
    );

    if (userQuery.rows.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    res.json({ user: userQuery.rows[0] });
  } catch (error) {
    console.error("Error obteniendo perfil:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Actualizar perfil
router.put("/profile", verifyToken, async (req, res) => {
  try {
    const { name, last_name } = req.body;
    const userId = req.user.id;

    if (!name || !last_name) {
      return res.status(400).json({ message: "Nombre y apellido son requeridos" });
    }

    await pool.query(
      "UPDATE users SET name = $1, last_name = $2 WHERE id = $3",
      [name, last_name, userId]
    );

    const updatedUser = await pool.query(
      "SELECT id, name, last_name, email FROM users WHERE id = $1",
      [userId]
    );

    res.json({ 
      message: "Perfil actualizado con éxito",
      user: updatedUser.rows[0]
    });
  } catch (error) {
    console.error("Error actualizando perfil:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

export { verifyToken };
export default router;
