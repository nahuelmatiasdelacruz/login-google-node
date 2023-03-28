const Role = require("../models/role");
const Usuario = require("../models/usuario");
const isValidRole = async (rol = "") => {
	const existeRol = await Role.findOne({ rol });
	if (!existeRol) {
		throw new Error(`El rol ${rol} no es válido`);
	}
};
const existeEmail = async (correo = "") => {
	const existeEmail = await Usuario.findOne({ correo });
	if (existeEmail) {
		throw new Error(`Este correo: ${correo} ya está registrado`);
	}
};
const existeUsuarioById = async (id = "") => {
	const existeUsuario = await Usuario.findById(id);
	if (!existeUsuario) {
		throw new Error(`El id: ${id} no existe`);
	}
};
module.exports = { isValidRole,existeEmail ,existeUsuarioById};
