from database import engine
import os
print("Raw DATABASE_URL:", repr(os.getenv("DATABASE_URL")))
import sqlalchemy as sa


conn = engine.connect()

print("Tables:")
result = conn.execute(sa.text("SELECT table_name FROM information_schema.tables WHERE table_schema='public'"))
for row in result:
    print(" -", row[0])

print("\nAlembic version:")
result = conn.execute(sa.text("SELECT version_num FROM alembic_version"))
for row in result:
    print(" -", row[0])

print("\nIndexes on anomalies:")
result = conn.execute(sa.text("SELECT indexname FROM pg_indexes WHERE tablename='anomalies'"))
for row in result:
    print(" -", row[0])

print("\nColumns on users:")
result = conn.execute(sa.text("SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'"))
for row in result:
    print(" -", row[0], ":", row[1])