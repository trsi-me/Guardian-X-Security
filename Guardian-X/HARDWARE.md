# Guardian-X — الربط بالهاردوير مستقبلاً

## نظرة عامة

المشروع مُصمَّم لدعم الربط بأجهزة الحافة (Edge) المذكورة في التقرير:
- **Raspberry Pi**
- **Mini-PC**
- أي جهاز Linux/Windows

حالياً يعمل في وضع **المحاكاة**، مع إمكانية الترقية للهاردوير الفعلي لاحقاً.

---

## البنية الحالية vs المستقبلية

| المكون | الحالي | مستقبلاً (الهاردوير) |
|--------|--------|------------------------|
| Edge Agent | `agent/edge_agent.py` يعمل على أي جهاز | نفس السكربت على Raspberry Pi |
| الاتصال | HTTP عادي | HTTPS (TLS 1.3) |
| التسجيل | يدوي أو محاكاة | تسجيل تلقائي بـ `agent_id` |
| ML على الحافة | لا (التحليل على السيرفر) | Isolation Forest محلي اختياري |

---

## خطوات الربط بـ Raspberry Pi مستقبلاً

### 1. تجهيز Raspberry Pi

```bash
# تثبيت Python و المتطلبات
sudo apt update
sudo apt install python3 python3-pip
pip3 install watchdog requests
```

### 2. نسخ المشروع

```bash
scp -r Guardian-X/ pi@<RASPBERRY_IP>:~/
```

### 3. تشغيل الوكيل

```bash
ssh pi@<RASPBERRY_IP>
cd Guardian-X
python3 agent/edge_agent.py \
  --path /home/pi/Documents \
  --server http://<SERVER_IP>:5000 \
  --user "raspberry-pi-01"
```

### 4. (مستقبلاً) تفعيل TLS

عند توفر شهادة SSL:
- تعديل `config.py`: `use_tls = True`
- إضافة `tls_cert_path`

### 5. (مستقبلاً) ML محلي على الحافة

عند إضافة نماذج خفيفة للوكيل:
- نسخ `isolation_forest.pkl` إلى الوكيل
- تفعيل `local_ml_on_edge` في `config.py`

---

## API للوكيل الفعلي

الوكيل يرسل `agent_id` اختيارياً. عند الربط بالهاردوير:

```json
POST /api/events
{
  "user_id": "raspberry-pi-01",
  "activity_type": "Create",
  "file_path": "/home/pi/data/file.txt",
  "agent_id": "raspberry-pi-01"
}
```

السيرفر يسجّل الوكيل تلقائياً في جدول `agents` مع `source: 'hardware'`.

---

## الملفات ذات الصلة

- `config.py` — إعدادات الربط والهاردوير
- `agent/edge_agent.py` — الوكيل (يعمل على أي جهاز)
- `server/app.py` — يستقبل من الوكلاء الفعلية والمحاكاة
