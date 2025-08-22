import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import cors from "cors";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cors({
  origin: "http://localhost:4321",
  credentials: true,
}));
app.use("/auth", authRoutes);

app.listen(process.env.PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${process.env.PORT}`);
});
