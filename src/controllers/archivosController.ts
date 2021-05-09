// import fs from "fs";
// import path from "path";
// import { Request, Response } from "express";
// import subirArchivo from "../helpers/subirArchivo";
// import usuario from "../models/mongo/usuario";

// export const cargarArchivo = async (req: Request, res: Response) => {
//   if (!req.files || Object.keys(req.files).length === 0 || !req.files.archivo) {
//     return res.status(400).json({ msg: "No has enviado ningun archivo" });
//   }

//   const nombre = await subirArchivo(
//     req.files,
//     ["jpg", "jpeg", "png"],
//     "carpetaImagenes"
//   );

//   return res.status(200).json({ nombre });
// };

// export const actualizarImagen = async (req: Request, res: Response) => {
//   const { coleccion, id } = req.params;

//   if (!req.files || Object.keys(req.files).length === 0 || !req.files.archivo) {
//     return res.status(400).json({ msg: "No has enviado ningun archivo" });
//   }

//   let modelo;

//   switch (coleccion) {
//     case "usuarios":
//       modelo = await usuario.findById(id);
//       if (!modelo) {
//         return res.status(400).json({
//           msg: `No existe un usuario con el id ${id}`,
//         });
//       }

//       break;

//     default:
//       return res.status(500).json({ msg: "No existe la coleccion que buscas" });
//   }

//   // Limpiar imágenes previas
//   if (modelo.img) {
//     // Hay que borrar la imagen del servidor
//     const pathImagen = path.join(
//       __dirname,
//       "../uploads",
//       coleccion,
//       modelo.img
//     );
//     if (fs.existsSync(pathImagen)) {
//       fs.unlinkSync(pathImagen);
//     }
//   }

//   const nombre: any = await subirArchivo(req.files, [], coleccion);
//   modelo.img = nombre.toString();

//   await modelo.save();

//   res.json({ msg: "" });
// };

// export const mostrarImagen = async (req: Request, res: Response) => {
//   const { id, coleccion } = req.params;

//   let modelo;

//   switch (coleccion) {
//     case "usuarios":
//       modelo = await usuario.findById(id);
//       if (!modelo) {
//         return res.status(400).json({
//           msg: `No existe un usuario con el id ${id}`,
//         });
//       }

//       break;

//     default:
//       return res.status(500).json({ msg: "No existe la coleccion que buscas" });
//   }

//   if (modelo.img) {
//     const pathImagen = path.join(
//       __dirname,
//       "../uploads",
//       coleccion,
//       modelo.img
//     );
//     if (fs.existsSync(pathImagen)) {
//       return res.sendFile(pathImagen);
//     }
//   }

//   const pathImagen = path.join(__dirname, "../assets/no-image.jpg");
//   res.sendFile(pathImagen);
// };
