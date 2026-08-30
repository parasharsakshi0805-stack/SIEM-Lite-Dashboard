from dotenv import dotenv_values
import subprocess

env = dotenv_values("backend/.env")
url = env.get("DATABASE_URL", "")

# postgresql://postgres:PASSWORD@host:port/db
password = url.split("postgres:")[1].split("@")[0]

sql = f"ALTER USER postgres WITH PASSWORD '{password}';"

result = subprocess.run(
    ["docker", "exec", "-i", "siem-postgres", "psql", "-U", "postgres", "-c", sql],
    capture_output=True, text=True
)

print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("Return code:", result.returncode)