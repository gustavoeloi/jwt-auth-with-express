import { Router } from "express";
import { ProductsController } from "@/controllers/products-controller";
import { ensureAuth } from "@/middlewares/ensureAuthentication";
import { verifyUserAuthorization } from "@/middlewares/verifyUserAuthorization";

const productsRoutes = Router();
const productsController = new ProductsController();

productsRoutes.get("/", productsController.index);
productsRoutes.post(
  "/",
  ensureAuth,
  verifyUserAuthorization(["admin", "seller"]),
  productsController.create
);

export { productsRoutes };
