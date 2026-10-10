"""Approved Identity roles, permissions, and assignment policy."""

ROLE_CATALOG = {
    "ADMIN": "Administrador global del sistema.",
    "AGENCY_ADMIN": "Administrador limitado a una agencia.",
    "SECRETARY": "Operaciones de agencia y atencion al cliente.",
    "LOADER": "Operaciones de carga y acomodo.",
    "DRIVER": "Operaciones de transporte.",
}

OPERATIONAL_ROLE_NAMES = frozenset({"SECRETARY", "LOADER", "DRIVER"})

PERMISSION_CATALOG = {
    "USERS_READ": "Consultar usuarios internos.",
    "USERS_CREATE": "Crear usuarios internos.",
    "USERS_UPDATE": "Actualizar y desactivar usuarios internos.",
    "USERS_ASSIGN_ROLE": "Asignar o cambiar roles operativos aprobados.",
    "ROLES_READ": "Consultar roles aprobados.",
    "ROLES_PERMISSIONS_MANAGE": "Asignar o retirar permisos aprobados de roles.",
    "PERMISSIONS_READ": "Consultar permisos aprobados.",
}

PERMISSION_ASSIGNABLE_ROLES = {
    permission_name: frozenset({"ADMIN"})
    for permission_name in PERMISSION_CATALOG
}
