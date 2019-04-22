# coding: utf-8

from pyshark.packet.layer import Layer

from csl.core import logger
from csl.core.session import Session


def analyse(session: Session, layer: Layer) -> bool:

    current_creds = session.credentials_being_built

    if hasattr(layer, "authtype"):
        # values signification can be found here https://www.postgresql.org/docs/8.2/protocol-message-formats.html
        auth_type = int(layer.authtype)

        if auth_type == 5:
            current_creds.context["auth_type"] = "md5"

        elif auth_type == 4:
            current_creds.context["auth_type"] = "crypt"

        elif auth_type == 3:
            current_creds.context["auth_type"] = "cleartext"

        elif auth_type == 10:
            current_creds.context["auth_type"] = "sasl"

        elif auth_type == 0 and current_creds.username:
            if current_creds.hash:
                logger.found(session, "credentials found ! Username: {} | Hash: {} | Salt: {}".format(current_creds.username, current_creds.hash, current_creds.context["salt"]))
            elif current_creds.password:
                logger.found(session, "credentials found ! Username: {} | Password: {}".format(current_creds.username, current_creds.password))
            else:
                logger.found(session, "it seems that '{}' authenticated without password".format(current_creds.username))

            if "database" in current_creds.context:
                logger.info("Targeting database '{}'".format(current_creds.context["database"]))

            return True

    if hasattr(layer, "parameter_name"):

        # Sometimes tshark returns multiple fields with the same name
        parameter_names = layer.parameter_name.all_fields
        parameter_values = layer.parameter_value.all_fields

        for i in range(len(parameter_names)):

            parameter_name = parameter_names[i].show
            parameter_value = parameter_values[i].show

            if parameter_name == "user":
                current_creds.username = parameter_value

            elif parameter_name == "database":
                current_creds.context["database"] = parameter_value

            elif parameter_name == "server_version":
                logger.info(session, "PostgreSQL version: " + parameter_value)

    if hasattr(layer, "salt"):
        current_creds.context["salt"] = layer.salt.replace(":", "")

    elif hasattr(layer, "password"):

        if "auth_type" in current_creds.context and current_creds.context["auth_type"] != "cleartext":
            current_creds.hash = layer.password
            auth_type = current_creds.context["auth_type"]

            # Remove the hash type from the hash string
            if current_creds.hash.startswith(auth_type):
                current_creds.hash = current_creds.hash[len(auth_type):]

        else:
            current_creds.password = layer.password

    return False
