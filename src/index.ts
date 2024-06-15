import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { sign } from "hono/jwt";
import axios from "axios";
import { jwt } from "hono/jwt";
import type { JwtVariables } from "hono/jwt";

type Variables = JwtVariables;

const app = new Hono<{ Variables: Variables }>();
const prisma = new PrismaClient();
const SECRET_KEY = "mySecretKey";
const BCRYPT_COST = 4;

app.use("/*", cors());

app.use(
  "/protected/*",
  jwt({
    secret: SECRET_KEY,
  })
);

// Endpoint for registration
app.post("/register", async (c) => {
  const { email, password } = await c.req.json();
  const hashedPassword = await Bun.password.hash(password, {
    algorithm: "bcrypt",
    cost: BCRYPT_COST,
  });

  try {
    const user = await prisma.user.create({
      data: { email, hashedPassword },
    });

    return c.json({ message: `${user.email} created successfully` });
  } catch (e) {
    if (
      e instanceof Prisma.PrismaClientKnownRequestError &&
      e.code === "P2002"
    ) {
      return c.json({ message: "Email already exists" });
    }
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Endpoint for login
app.post("/login", async (c) => {
  const { email, password } = await c.req.json();

  try {
    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return c.json({ message: "User not found" }, 404);
    }

    const match = await Bun.password.verify(
      password,
      user.hashedPassword,
      "bcrypt"
    );

    if (!match) {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    const payload = {
      sub: user.id,
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
    };
    const token = await sign(payload, SECRET_KEY);

    return c.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Endpoint to get Pokémon by name
app.get("/pokemon/:name", async (c) => {
  const { name } = c.req.param();

  try {
    const response = await axios.get(
      `https://pokeapi.co/api/v2/pokemon/${name}`
    );
    return c.json({ data: response.data });
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response && error.response.status === 404) {
        return c.json({ message: "Your Pokémon was not found!" }, 404);
      }
      return c.json(
        { message: "An error occurred while fetching the Pokémon data" },
        500
      );
    }
    return c.json({ message: "An unexpected error occurred" }, 500);
  }
});

// Endpoint to catch Pokémon and save to the database
app.post("/protected/catch", async (c) => {
  const payload = c.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  const { name: pokemonName } = await c.req.json();

  if (!pokemonName) {
    throw new HTTPException(400, { message: "Pokemon name is required" });
  }

  try {
    let pokemon = await prisma.pokemon.findUnique({
      where: { name: pokemonName },
    });

    if (!pokemon) {
      pokemon = await prisma.pokemon.create({ data: { name: pokemonName } });
    }

    const caughtPokemon = await prisma.caughtPokemon.create({
      data: {
        userId: payload.sub,
        pokemonId: pokemon.id,
      },
    });

    return c.json({ message: "Pokemon caught", data: caughtPokemon });
  } catch (error) {
    console.error("Error catching Pokémon:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Endpoint to release Pokémon from the database
app.delete("/protected/release/:id", async (c) => {
  const payload = c.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  const { id } = c.req.param();

  try {
    const deleteResult = await prisma.caughtPokemon.deleteMany({
      where: { id, userId: payload.sub },
    });

    if (deleteResult.count === 0) {
      return c.json({ message: "Pokemon not found or not owned by user" }, 404);
    }

    return c.json({ message: "Pokemon is released" });
  } catch (error) {
    console.error("Error releasing Pokémon:", error);
    return c.json(
      { message: "An error occurred while releasing the Pokemon" },
      500
    );
  }
});

// Endpoint to get the list of caught Pokémon
app.get("/protected/caught", async (c) => {
  const payload = c.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  try {
    const caughtPokemon = await prisma.caughtPokemon.findMany({
      where: { userId: payload.sub },
      include: { pokemon: true },
    });

    if (caughtPokemon.length === 0) {
      return c.json({ message: "No Pokémon found." });
    }

    return c.json({ data: caughtPokemon });
  } catch (error) {
    console.error("Error fetching caught Pokémon:", error);
    return c.json(
      { message: "An error occurred while fetching caught Pokémon" },
      500
    );
  }
});

export default app;
