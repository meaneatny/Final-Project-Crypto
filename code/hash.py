from passlib.hash import bcrypt

hash_from_users_json = "$2a$12$.F8itPimbHn0o5ov2Fb0zOrstbhOaJorczk1ufNkG5kYiKmERP5JK"

print(bcrypt.verify("Admin123", hash_from_users_json))
