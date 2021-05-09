import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import usuario, { Iusuario } from "../models/mongo/usuario";

// CONFIGURACIONES SOLO PARA TS

declare global {
  // utilizamos esto para extender la propiedades de Request
  namespace Express {
    interface Request {
      userId: string; //asignamos la nueva propiedad
    }
  }
}

// creamos la interfaz para que no no de error por lo que retorna jwt.verify()
export interface IPayload {
  id: string;
  iat: number;
}

// AQUI EMPIEZA NUESTRO CODIGO

export const verifyToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let token = req.headers["x-access-token"] as string;
  let SECRET = process.env.JWT_SECRET as string;

  if (!token) {
    return res.status(403).json({ msg: "Envia tu token para proceder" });
  }

  try {
    const decoded = jwt.verify(token, SECRET) as any; // asignamos la interfaz
    req.userId = decoded.id;

    return next();
  } catch (error) {
    return res.status(401).json({ msg: "Acceso Denegado" });
  }
};

export const isModerador = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.userId) {
    return res.status(500).json({
      msg: "Se intenta realizar la accion sin antes validar el token",
    });
  }

  try {
    let user = (await usuario.findOne(
      { _id: req.userId },
      { password: 0 }
    )) as Iusuario;

    if (user.rol === process.env.ROL_MODERADOR) {
      return next();
    }

    return res.status(403).json({ msg: "No tienes permisos para esta ruta" });
  } catch (error) {
    return res.status(500).json({ error });
  }
};

export const isAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.userId) {
    return res.status(500).json({
      msg: "Se intenta realizar la accion sin antes validar el token",
    });
  }

  try {
    let user = (await usuario.findById(
      { _id: req.userId },
      { password: 0 }
    )) as Iusuario;

    if (user.rol === process.env.ROL_ADMIN) {
      return next();
    }

    return res.status(403).json({ msg: "No tienes permisos para esta ruta" });
  } catch (error) {
    return res.status(500).json({ error });
  }
};
