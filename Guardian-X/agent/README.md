# Guardian-X Edge Agent

## مراقبة أنشطة الملفات بشكل تلقائي (Real-Time File System Monitoring)

العميل يعمل على الجهاز (Edge) ويراقب مجلدات محددة. عند أي إنشاء/تعديل/حذف لملف، يرسل الحدث تلقائياً للسيرفر لتحليله بالذكاء الاصطناعي.

## التثبيت

```bash
pip install watchdog requests
```

## التشغيل

```bash
# مراقبة المجلد الحالي (أو Documents على Windows)
python agent/edge_agent.py

# مراقبة مجلد محدد
python agent/edge_agent.py --path "C:\Users\YourName\Documents"

# مع خادم على عنوان مختلف
python agent/edge_agent.py --server http://192.168.1.100:5000

# مع معرف نقطة النهاية
python agent/edge_agent.py --user "workstation-01"
```

## الخيارات

| الخيار | الوصف | الافتراضي |
|--------|-------|-----------|
| `--path`, `-p` | المجلد للمراقبة | `.` أو `Documents` |
| `--server`, `-s` | عنوان خادم Guardian-X | `http://127.0.0.1:5000` |
| `--user`, `-u` | معرف الجهاز/المستخدم | اسم الجهاز (hostname) |
| `--ignore`, `-i` | تجاهل مسارات تحتوي على | `.git`, `__pycache__`, `node_modules` |

## مثال

```bash
python agent/edge_agent.py -p "D:\Projects" -u "dev-pc" -i ".git" -i "node_modules"
```

## ملاحظة

- تأكد أن خادم Guardian-X يعمل (`python server/app.py`) قبل تشغيل العميل
- العميل يرسل Create, Modify, Delete فقط (Read لا يمكن رصده من نظام الملفات)
- الأحداث تُحلل فوراً بواسطة القواعد + مجموعة ML + XAI
