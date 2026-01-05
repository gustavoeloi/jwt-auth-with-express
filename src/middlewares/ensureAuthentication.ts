import { AppError } from "@/utils/AppError";
import { Response, Request, NextFunction } from "express";
import { authConfig } from "@/configs/auth";

import { verify } from "jsonwebtoken";

interface tokenPayload {
  role: string;
  sub: string;
}

function ensureAuth(request: Request, response: Response, next: NextFunction) {
  const token = request.headers.authorization;

  if (!token) {
    throw new AppError("Invalid token session!", 401);
  }

  const [_, jwt] = token.split(" ");

  const { sub: userId, role } = verify(
    jwt,
    authConfig.jwt.secret
  ) as tokenPayload;

  request.user = {
    id: String(userId),
    role,
  };

  next();
}

export { ensureAuth };
