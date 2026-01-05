import { Request, Response, NextFunction } from "express";
import { AppError } from "@/utils/AppError";

function verifyUserAuthorization(roles: string[]) {
  return (request: Request, response: Response, next: NextFunction) => {
    if (!request.user || !roles.includes(request.user.role)) {
      throw new AppError("Unauthorized", 401);
    }

    return next();
  };
}

export { verifyUserAuthorization };
