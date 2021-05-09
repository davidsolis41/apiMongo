import { Request, Response } from "express";
import usuario from "../models/mongo/usuario";
import jwt from "jsonwebtoken";
import { compare, genSalt, hash } from "bcrypt";

export async function registroUsuario(req: Request, res: Response) {
  let { email, password } = req.body;
  email.toString();
  password.toString();
  try {
    let comprobarEmail = await usuario.findOne(
      { email },
      { password: 0, rol: 0 }
    );

    if (comprobarEmail) {
      return res.status(400).json({
        msg: "El correo ingresado ya pertenece a un usuario",
        alertType: "error",
      });
    }

    let salt = await genSalt(12);
    password = await hash(password.toString(), salt);

    let nuevoUsuario = await new usuario({
      email,
      password,
      rol: process.env.ROL_USUARIO,
    }).save();

    return res
      .status(201)
      .json({ msg: "Registro exitoso", registro: true, redirect: true });
  } catch (error) {
    console.log(error);

    return res.status(400).json({
      msg: "Error al registrar, intente nuevamente",
      registro: false,
      redirect: false,
    });
  }
}

export async function registroModerador(req: Request, res: Response) {
  let { email, password } = req.body;
  email.toString();
  password.toString();
  try {
    let comprobarEmail = await usuario.findOne(
      { email },
      { password: 0, rol: 0 }
    );

    if (comprobarEmail) {
      return res.status(400).json({
        msg: "El correo ingresado ya pertenece a un usuario",
        alertType: "error",
      });
    }

    let salt = await genSalt(12);
    password = await hash(password.toString(), salt);

    let nuevoUsuario = await new usuario({
      email,
      password,
      rol: process.env.ROL_MODERADOR,
    }).save();

    return res
      .status(201)
      .json({ msg: "Registro exitoso", registro: true, redirect: true });
  } catch (error) {
    console.log(error);

    return res.status(400).json({
      msg: "Error al registrar, intente nuevamente",
      registro: false,
      redirect: false,
    });
  }
}

export async function login(req: Request, res: Response) {
  let { email, password } = req.body;
  const SECRET = process.env.JWT_SECRET as string;
  try {
    let comprobarEmail: any = await usuario.findOne({ email }, { rol: 0 });

    if (!comprobarEmail) {
      return res.status(400).json({
        msg: "El correo ingresado no existe en el sistema",
        alertType: "error",
      });
    }

    let comprobacionUsuario: boolean = await compare(
      password.toString(),
      comprobarEmail.password
    );

    if (comprobacionUsuario) {
      let token: string = jwt.sign({ id: comprobarEmail._id }, SECRET, {
        expiresIn: 86400,
      });

      return res.status(200).json({ token, loggin: true, redirect: true });
    }
  } catch (error) {
    console.log(error);
    return res.status(400).json({
      msg: `ocurrio un fallo al iniciar sesion, intenta nuevamente ${error}`,
      loggin: false,
      redirect: false,
    });
  }
}
