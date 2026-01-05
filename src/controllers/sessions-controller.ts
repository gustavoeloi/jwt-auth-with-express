import { AppError } from "@/utils/AppError";
import { Request, Response } from "express";
import { authConfig } from "@/configs/auth";
import { sign } from "jsonwebtoken";

class SessionsController {
  async create(request: Request, response: Response) {
    const { username, password } = request.body;

    const fakeuser = {
      id: 1,
      username: "eloidev",
      password: "123456",
      role: "seller",
    };

    if (username !== fakeuser.username || password !== fakeuser.password) {
      throw new AppError("Nome de usuário e/ou senha incorreta!", 401);
    }

    const { secret, expiresIn } = authConfig.jwt;

    const token = sign(
      {
        role: fakeuser.role,
      },
      secret,
      {
        subject: String(fakeuser.id),
        expiresIn,
      }
    );

    return response.json({ token });
  }
}

export { SessionsController };
