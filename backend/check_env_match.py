from dotenv import dotenv_values

backend_env = dotenv_values("backend/.env")
root_env = dotenv_values(".env")

def extract_password(url):
    # postgresql://postgres:PASSWORD@host:port/db
    try:
        return url.split("postgres:")[1].split("@")[0]
    except Exception:
        return None

backend_pw = extract_password(backend_env.get("DATABASE_URL", ""))
root_pw = extract_password(root_env.get("DATABASE_URL", ""))
root_pw2 = root_env.get("POSTGRES_PASSWORD", "")

print("backend/.env password matches root .env DATABASE_URL:", backend_pw == root_pw)
print("root .env DATABASE_URL matches root .env POSTGRES_PASSWORD:", root_pw == root_pw2)
print("backend SECRET_KEY set:", bool(backend_env.get("SECRET_KEY")))
print("root SECRET_KEY set:", bool(root_env.get("SECRET_KEY")))