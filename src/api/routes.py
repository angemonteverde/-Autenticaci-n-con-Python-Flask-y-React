"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

api = Blueprint('api', __name__)

@api.route('/user', methods=['POST'])
def add_new_useer():

    body = json.loads(request.data)
    user_password = body["password"]


    # Mensajes campos sin completar
    if not body["name"]:
        return jsonify({"msg": "Introduzca nombre"}), 401
    if not body["email"]:
        return jsonify({"msg": "Introduzca un correo"}), 401
    if not body["password"]:
        return jsonify({"msg": "Introduzca una contraseña"}), 401


    # Comprobamos si el correo o el nombre ya están registrados
    nombre_existente = User.query.filter_by(name = body["name"]).first()
    correo_existente = User.query.filter_by(email = body["email"]).first()

    if nombre_existente is not None or correo_existente is not None:
        return jsonify({"msg":"El nombre o correo ya está registrado"})

    
    # Hash password
    hashed_password = current_app.bcrypt.generate_password_hash(body["password"]).decode('utf-8')

    # Guardar nuevo user con hased_password
    user = User(name = body["name"], email=body["email"], password = hashed_password)
    db.session.add(user)
    db.session.commit()

    # Respuesta
    response_body = {
        "msg": "user created"
    }

    return jsonify(response_body), 200


# Delete User

@api.route('/user', methods=['PUT'])
def delete_user():

    body = json.loads(request.data)
    usuario = User.query.filter_by(name= body["name"]).first()

    db.session.delete(usuario)
    db.session.commit()

    response_body = {
        "msg": "user deleted"
    }

    return jsonify(response_body), 200


# Login
# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@api.route("/login", methods=["POST"])
def login():

    email = request.json.get("email", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(email=email).first()
    user_by_name = User.query.filter_by(name=email).first()

    # Mensajes datos sin rellenar
    if not email:
        return jsonify({"msg": "Introduzca un correo"}), 401
    if not password:
        return jsonify({"msg": "Introduzca una contraseña"}), 401


    # Mensaje usuario no registrado
    if user is None and user_by_name is None:
        return jsonify({"msg": "Usuario no encontrado"}), 401


    if user :

        if email != user.email or  current_app.bcrypt.check_password_hash(user.password,password) == False:
            return jsonify({"msg": "Bad username or password"}), 401
        
        access_token={
            "token": create_access_token(identity=email),
            "name": user.name
        }


    if user_by_name and not user:
        if email != user_by_name.name  or  current_app.bcrypt.check_password_hash(user_by_name.password,password) == False:
            return jsonify({"msg": "Bad username or password"}), 401
        
        access_token={
            "token": create_access_token(identity=email),
            "name": user_by_name.name
        }

    return jsonify(access_token= access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@api.route("/profile", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()
