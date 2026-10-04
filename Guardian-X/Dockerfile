FROM python:3.10-slim

WORKDIR /app

# تثبيت المتطلبات
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ كل الملفات
COPY . .

# إنشاء مجلد النماذج
RUN mkdir -p server/models

EXPOSE 5000

CMD ["python", "server/app.py"]
