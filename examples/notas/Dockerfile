FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV NOTAS_DB=/data/notas.db
EXPOSE 8000
CMD ["sh", "-c", "[ -f \"$NOTAS_DB\" ] || python scripts/init_db.py --db \"$NOTAS_DB\"; exec uvicorn notas.main:app --host 0.0.0.0 --port 8000"]
