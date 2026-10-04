# Guardian-X Security

نظام Python لكشف الشذوذ في نشاط الملفات على الجهاز، مع لوحة ويب ونماذج تعلم آلي. المصدر المقروء هو `Guardian-X`. يوجد مجلد ثان باسم `Gurdian-X` يضم نسخة مصدر مشابهة.

## 1. ما هو المشروع؟

حسب `Guardian-X\README.md`: نظام لاكتشاف السلوك غير المعتاد لمستخدمي الحواسيب عبر أنشطة الملفات (إنشاء، قراءة، تعديل، حذف) على الحافة. يجمع قواعدا ثابتة وتعلمًا آليًا وتفسيرا (SHAP و LIME). الكود يضيف أيضا مسارات معاملات دخول ومحاكاة، وخط أساس متكيف، وإجراءات احتواء تُسجَّل في SQLite.

## 2. لماذا يوجد هذا المشروع؟

الوثيقة الداخلية تصف كشفا مبكرا لتهديدات مرتبطة بسلوك الملفات. `config.py` يوثق إطار NIST CSF 2.0 مع تعيين إلى ISO/IEC 27001:2022، ويظهر عبر `GET /api/security/framework`.

## 3. من يستخدمه؟

مستخدم لوحة `frontend\index.html`. وكيل حافة يرسل الأحداث (`agent\edge_agent.py`). معرفات مثل `user_id` و `agent_id` حقول في الجداول. أدوار صلاحيات (مدير/مستخدم) غير موجودة في مخطط `db.py`.

## 4. ماذا يستطيع النظام أن يفعل؟

من `server\app.py` والملفات المجاورة:

| الوظيفة | الملف أو المسار |
| --- | --- |
| عرض اللوحة | `GET /` وملفات `frontend` |
| استقبال أحداث ملفات | `POST /api/events` |
| عرض أحداث وتنبيهات وإحصاءات | `GET /api/events` و `/api/alerts` و `/api/stats` |
| صحة الخدمة | `GET /api/health` |
| مقاييس | `GET /api/metrics` |
| وكلاء ونبض | `GET /api/agents` و `POST /api/agents/heartbeat` |
| تفسير حدث | `GET /api/explain/<event_id>` |
| تدريب | `POST /api/train` و `server\train_models.py` |
| تقييم | `POST /api/evaluation/run` و `server\evaluation.py` |
| احتواء مسجّل | `GET/POST /api/containment` |
| ملف سلوكي | `GET /api/profile` |
| تحليل محاولة دخول | `POST /api/login` و `GET /api/login/stats/<user_id>` |
| محاكاة داخلية | مسارات `POST /api/simulate/...` و `POST /api/scenarios/fraud` و `POST /api/scenarios/unauthorized_copy` |
| مراقبة ملفات | `agent\edge_agent.py` عبر مكتبة watchdog |
| قواعد | `server\rules.py` |
| نماذج | `server\ml_models.py` و `server\ai_model.py` |
| ميزات | `server\feature_extractor.py` |
| تفسير | `server\explainability.py` |
| خط أساس | `server\adaptive_baseline.py` |
| طابور | `server\queue_worker.py` |

مسارات المحاكاة تشغّل سيناريوهات معرّفة داخل المشروع لفحص الكشف. هذه الوثيقة تصف وجودها ولا تضيف خطوات هجوم.

## 5. كيف يعمل النظام؟

```
Edge Agent أو نموذج اللوحة
  -> POST /api/events
  -> rules.py ثم نماذج ML
  -> file_events و alerts و explanations
  -> containment_actions عند المسار الخاص بالاحتواء
  -> الواجهة تقرأ JSON من /api/*
```

`config.py` يضبط `MODE = 'simulation'`. التعليق في الملف يذكر أيضا القيم `hybrid` و `hardware`.

## 6. أمثلة واقعية

رصد حدث ملف يصل إلى الخادم:

1. الوكيل أو الواجهة يرسل الحدث إلى `POST /api/events`.
2. `add_event` يعالج الحدث، مع `_adapt_baseline_if_needed` عند الحاجة.
3. الصف يُحفظ في `file_events` مع `risk_level`.
4. تنبيه محتمل في `alerts`.
5. التفسير عبر `GET /api/explain/<event_id>` من `explanations`.

تدريب أول مرة، من الوثيقة الداخلية: `python server\train_models.py` من مجلد `Guardian-X`.

## 7. رحلة المستخدم

فتح `http://127.0.0.1:5000` بعد تشغيل `server\app.py`. الصفحة `frontend\index.html`. اختيار عرض الأحداث أو التنبيهات أو التدريب من الواجهة (`script.js`). نتيجة الحدث تظهر في اللوحة بعد استدعاء الواجهات. حساب دخول للوحة غير ظاهر في مسارات `app.py`.

## 8. الوحدات والأقسام

| الوحدة | الوظيفة من الملفات |
| --- | --- |
| `agent` | إرسال نشاط الملفات إلى الخادم |
| `server` | Flask والتحليل والتخزين |
| `frontend` | HTML و CSS و JavaScript |
| `dataset\archive` | ملفات CSV محلية كبيرة |
| `dataset\synthetic` | ملفات CSV اصطناعية صغيرة |
| `config.py` | وضع التشغيل وإطار الأمن وعتبات مبالغ |
| `guardian_service.py` | ملف خدمة في جذر `Guardian-X` |
| `Gurdian-X\Guardian-X` | نسخة مصدر ثانية |

## 9. الشركات والكيانات

هيكل شركات متعدد غير موجود في الملفات الحالية. العتبات في `TRANSACTION_THRESHOLDS` تخص مبالغا (`suspicious_amount` و `high_risk_amount`) داخل وضع التحليل، وليست سجل شركات.

## 10. الصلاحيات

نظام أدوار للمستخدمين غير موجود في `db.py`. الواجهات في `app.py` بلا دالة تسجيل دخول للوحة. الوكيل يُعرَّف بـ `agent_id`.

## 11. الأتمتة وWorkflows

| السلوك | الدليل |
| --- | --- |
| خط أساس يتحدث | `adaptive_baseline.py` و `_adapt_baseline_if_needed` |
| احتواء يُسجَّل | جدول `containment_actions`، والحالة الافتراضية في المخطط `simulated` |
| عامل طابور | `queue_worker.py` ودالة `_publish_to_queue` |
| خدمة Docker | `docker-compose.yml` يعيد تشغيل الخادم والوكيل |

محرك موافقات بشري متعدد الخطوات غير موجود في الملفات الحالية.

## 12. التكامل بين الوحدات

الحدث يدخل `file_events`. التنبيه يرتبط بالأحداث عبر `file_event_ids`. التفسير يرتبط بـ `file_event_id`. الاحتواء يرتبط بـ `alert_id` أو `file_event_id`. الوكيل يسجل في `agents`. التدريب يقرأ بيانات من `server\training.py` ومن مجلد `dataset`.

## 13. المصطلحات

| المصطلح | المعنى من وثيقة المشروع والكود |
| --- | --- |
| Edge | معالجة على جهاز محلي عبر الوكيل |
| watchdog | مكتبة مراقبة ملفات مذكورة في `requirements.txt` |
| Isolation Forest و LightGBM و Autoencoder | نماذج مذكورة في `requirements.txt` و `ml_models.py` |
| SHAP و LIME | تفسير في `explainability.py` |
| NIST CSF 2.0 | قيمة `SECURITY_FRAMEWORK` |
| MTTD و MTTR | أعمدة `mttd_seconds` و `mttr_seconds` |

## 14. الأسئلة الشائعة

| السؤال | الجواب |
| --- | --- |
| هل البيانات الكبيرة جزء من الكود؟ | ملفات CSV محلية تحت `dataset\archive`. المحتوى غير ملصوق هنا |
| هل يلزم عتاد؟ | `MODE` الحالي `simulation`. `HARDWARE.md` يشرح ربط Raspberry Pi و Mini-PC |
| لماذا مجلدان؟ | `Guardian-X` و `Gurdian-X\Guardian-X` |
| أين القاعدة؟ | `server\guardian.db` حسب `DB_PATH` في `db.py` |

## 15. Architecture

```
frontend (index.html, script.js, style.css)
        | HTTP JSON
        v
server\app.py
  rules.py -> ai_model.py / ml_models.py -> explainability.py
  db.py -> guardian.db
        ^
agent\edge_agent.py
```

## 16. Tech Stack

من `requirements.txt` و `Dockerfile` و `app.py`: Python 3.10 في صورة Docker، Flask، requests، psutil، watchdog، scikit-learn، lightgbm، numpy، pandas، shap، lime، datasets. تعليق tensorflow اختياري وغير مفعّل في المتطلبات. الواجهة HTML/CSS/JS بلا إطار ظاهر. القاعدة SQLite.

## 17. Project Structure

```
Guardian-X Security
├── Guardian-X
│   ├── agent\edge_agent.py
│   ├── server\   app.py db.py rules.py ml_models.py ...
│   ├── frontend\
│   ├── dataset\archive\   CSV كبيرة
│   ├── dataset\synthetic\
│   ├── config.py
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   ├── HARDWARE.md
│   └── README.md
└── Gurdian-X\Guardian-X   نسخة مصدر
```

مجلدات `build` غير ذات صلة هنا. ملفات النماذج تُنشأ تحت `server\models` حسب Dockerfile.

## 18. Frontend

تطبيق صفحة واحدة: `frontend\index.html` مع `script.js` و `style.css`. `app.py` يخدم الأصل عبر `/assets/<path>` و `/<path>`. جلب البيانات من مسارات `/api/*` في `script.js`. سلوك متجاوب مفصل غير موثق خارج ملف CSS نفسه.

## 19. Backend

Flask في `server\app.py`. الدوال تشمل `add_event`, `get_alerts`, `train_models`, `trigger_containment`, `analyze_login_attempt`. الوصول للبيانات في `db.py` عبر `sqlite3`. أصناف متحكم منفصلة غير موجودة؛ الدوال مسجلة على `app` مباشرة.

## 20. Request Flow

```
المتصفح أو الوكيل
-> Flask app.py
-> دالة المسار
-> rules / ml_models / explainability
-> sqlite3 على guardian.db
-> JSON أو HTML
-> المتصفح
```

مثال حقيقي: `POST /api/events` يستدعي `add_event`.

## 21. Database

SQLite في `server\guardian.db`. الجداول من `init_db`:

| الجدول | أعمدة بارزة |
| --- | --- |
| `behavior_profile` | حدود عمليات ووقت عمل، وصف افتراضي واحد إن كان الجدول فارغا |
| `file_events` | `user_id`, `activity_type`, `file_path`, `risk_level`, `details` |
| `alerts` | `risk_level`, `reason`, `mttd_seconds` |
| `explanations` | `shap_json`, `lime_json`, `summary_text` |
| `containment_actions` | `action_type`, `status` الافتراضي `simulated`, `mttr_seconds` |
| `agents` | `agent_id`, `hostname`, `status`, `source` |

مهاجرات منفصلة غير موجودة في الملفات الحالية.

## 22. API

المصادقة على هذه المسارات غير ظاهرة في توقيعات `app.py` (بلا رمز جلسة للوحة). المنفذ الافتراضي 5000 من المتغير `PORT`.

| Method | Path | الغرض الظاهر |
| --- | --- | --- |
| GET | `/` | اللوحة |
| GET | `/api/events` | قائمة أحداث |
| POST | `/api/events` | إدخال حدث |
| GET | `/api/alerts` | تنبيهات |
| GET | `/api/stats` | إحصاءات |
| GET | `/api/health` | صحة |
| GET | `/api/security/framework` | إطار الأمن |
| POST | `/api/evaluation/run` | تقييم |
| POST | `/api/scenarios/fraud` | سيناريو معرّف في الكود |
| POST | `/api/scenarios/unauthorized_copy` | سيناريو معرّف في الكود |
| GET | `/api/metrics` | مقاييس |
| GET | `/api/agents` | وكلاء |
| POST | `/api/agents/heartbeat` | نبض وكيل |
| GET | `/api/profile` | ملف سلوكي |
| GET | `/api/explain/<event_id>` | تفسير |
| POST | `/api/train` | تدريب |
| GET, POST | `/api/containment` | عرض أو تسجيل احتواء |
| POST | `/api/simulate/transaction` | محاكاة معاملة |
| POST | `/api/simulate/batch` | محاكاة دفعة |
| POST | `/api/login` | تحليل محاولة دخول |
| GET | `/api/login/stats/<user_id>` | إحصاء دخول |
| POST | `/api/simulate/login` | محاكاة دخول |

شكل الجسم لكل طلب موثق داخل `script.js` و `app.py` أكثر من هذه الجدول. أسرار غير مطلوبة للمسارات حسب التوقيع الظاهر.

## 23. Authentication & Authorization

دخول مستخدم للوحة غير موجود في الملفات الحالية. `POST /api/login` اسمه في الكود `analyze_login_attempt`، أي تحليل محاولة وليس جلسة لوحة. TLS مذكور في `config.py`: `use_tls` بقيمة True ومسار `server\certs\cert.pem`. مجلد الشهادات لم يظهر في قائمة المصدر المفحوصة.

## 24. Security

| البند | الواقع |
| --- | --- |
| إطار موثق | NIST CSF 2.0 وربط ISO في `security_framework.py` |
| وكيل ملفات | watchdog على الجهاز الذي يشغّل الوكيل |
| احتواء | يُخزَّن ووضعه الافتراضي `simulated` |
| حماية واجهة API بكلمة مرور | غير موجودة في الملفات الحالية |
| CORS | دالة `add_cors` في `app.py` |
| تشغيل | `debug=False` و `host=0.0.0.0` في `app.run` |
| سجلات تدقيق مستقلة | الجداول `alerts` و `containment_actions` و `file_events` |

## 25. Configuration

| المصدر | المفاتيح |
| --- | --- |
| `config.py` | `SECURITY_FRAMEWORK`, `ISO_27001_MAPPING_ENABLED`, `MODE`, `HARDWARE` (منصات، `server_url`, `use_tls`, مسارات شهادة، `local_ml_on_edge`), `TRANSACTION_THRESHOLDS` |
| البيئة | `PORT` في `app.py`، و `FLASK_ENV` في `docker-compose.yml` |
| Docker | منفذ `5000:5000` ووحدات تخزين للنماذج و `guardian.db` |

قيم العناوين داخل `config.py` إعدادات ربط. لا تُنسخ أسرار إضافية لأن الملف لا يحتوي مفتاح API.

## 26. Integrations

HuggingFace `datasets` مذكور في المتطلبات لتعليق UNSW-NB15. Docker Compose. عتاد اختياري في `HARDWARE.md`. بريد وSMS وCloudflare غير موجودة في الملفات الحالية.

## 27. Scheduled Jobs

مهمة مجدولة بنظام cron غير موجودة في الملفات الحالية. `queue_worker.py` عامل في العملية. `restart: unless-stopped` في Compose يعيد تشغيل الحاوية.

## 28. File Storage

الأحداث تحفظ `file_path` نصا في SQLite. ملفات CSV تحت `dataset`. النماذج تحت `server\models`. قاعدة `guardian.db` ملف محلي، وCompose يربطها بحجم.

## 29. Logging & Monitoring

`GET /api/health` و `/api/metrics`. جداول التنبيهات والاحتواء تحمل أزمنة MTTD و MTTR. نظام تنبيه خارجي غير موجود في الملفات الحالية.

## 30. Installation

من مجلد `Guardian-X`، حسب README الداخلي:

```
pip install -r requirements.txt
python server\train_models.py
python server\app.py
```

الوكيل اختياري:

```
python agent\edge_agent.py --server http://127.0.0.1:5000 --user <اسم>
```

Docker من الملفات الحالية:

```
docker compose up --build
```

الخدمة `guardian-agent` تستدعي الوكيل بعنوان `http://guardian-server:5000`.

## 31. Development Guide

مسار جديد: دالة في `server\app.py` مع `@app.route`. جدول جديد: عبارة `CREATE TABLE` داخل `init_db` في `db.py`. قاعدة كشف: `server\rules.py`. نموذج: `server\ml_models.py` ثم تدريب `train_models.py`. الواجهة: `frontend\script.js`. صلاحية مستخدم: غير موجودة لتمتد منها.

## 32. Deployment

`Dockerfile` ينسخ المشروع ويشغّل `python server/app.py` على المنفذ 5000. `MODE` في الصورة يبقى قيمة `config.py` ما لم يُغيّر الملف. شهادات TLS المشار إليها تحتاج ملفات غير الظاهرة في الشجرة المفحوصة.

## 33. Backup & Recovery

نسخ مبرمج غير موجود في الملفات الحالية. الملف العملي هو `server\guardian.db` مع `server\models`.

## 34. Troubleshooting

| العرض | اتجاه الفحص |
| --- | --- |
| اللوحة بلا نماذج | تشغيل `train_models.py` حتى يُنشأ `server\models` |
| الوكيل لا يصل | عنوان `--server` وحاوية Compose |
| المنفذ مشغول | المتغير `PORT` |
| نسخة قديمة من السلوك | وجود مجلدين `Guardian-X` و `Gurdian-X` |

## 35. Dependencies

الإصدارات الدنيا في `requirements.txt`: flask>=2.3.0، requests>=2.28.0، psutil>=5.9.0، watchdog>=3.0.0، scikit-learn>=1.3.0، lightgbm>=4.0.0، numpy>=1.24.0، pandas>=2.0.0، shap>=0.43.0، lime>=0.2.0، datasets>=2.14.0.

## 36. Known Limitations

- وضع الكود الحالي `simulation`.
- احتواء بحالة افتراضية `simulated`.
- واجهات API بلا مصادقة ظاهرة.
- مجلدان للمصدر قد يفترقان عند التعديل.
- ملفات CSV الأرشيف كبيرة ومحلية.
- tensorflow معلّق كسطر تعليق في المتطلبات.

## 37. Current System State

| البند | الحالة |
| --- | --- |
| خادم ولوحة ووكيل ومخطط SQLite | موجودة كملفات |
| نماذج مدربة | المجلد يُنشأ عند التدريب أو عبر Docker |
| شهادات TLS | مسار مذكور، الملفات غير ظاهرة في الفحص |
| مجموعات بيانات | CSV محلية، صفوفها غير موثقة هنا |
| تشغيل فعلي أثناء الكتابة | غير موثق |

## 38. Architecture Decisions

- كشف على الحافة مع خادم Flask مركزي. الدليل: `edge_agent.py` و `app.py`.
- SQLite لملف واحد. الدليل: `db.py`.
- طبقات قواعد ثم ML ثم تفسير. الدليل: أسماء الملفات وREADME الداخلي.
- المحاكاة وضع افتراضي. الدليل: `MODE` في `config.py`.

## 39. سجل التغييرات

سجل إصدارات مستقل غير موجود في الملفات الحالية. README الداخلي يصف السلوك الحالي.

## مجموعات البيانات المحلية

تحت `Guardian-X\dataset\archive` (أحجام بالبايت). المحتوى غير منسوخ:

| الملف | الحجم |
| --- | --- |
| `UNSW-NB15_1.csv` | 168979718 |
| `UNSW-NB15_2.csv` | 165221021 |
| `UNSW-NB15_3.csv` | 154588103 |
| `UNSW-NB15_4.csv` | 97588754 |
| `NUSW-NB15_features.csv` | 4044 |

تحت `dataset\synthetic`: `banking_transactions_synthetic.csv` و `employee_activity_synthetic.csv` بحجم صغير.

## System Overview

```
[جهاز / محاكاة]
   edge_agent.py -- أحداث ملفات
        |
        v
   Flask :5000 -- قواعد + ML + تفسير
        |
        v
   guardian.db -- أحداث، تنبيهات، تفسير، احتواء، وكلاء
        |
        v
   لوحة frontend
```

## Quick Reference

| الجزء | التقنية | الموقع | الوظيفة |
| --- | --- | --- | --- |
| الخادم | Flask | `server\app.py` | API ولوحة |
| البيانات | SQLite | `server\db.py` | الجداول |
| القواعد | Python | `server\rules.py` | طبقة قواعد |
| النماذج | sklearn / lightgbm | `server\ml_models.py` | تصنيف وشذوذ |
| التفسير | SHAP / LIME | `server\explainability.py` | تفسير |
| الوكيل | watchdog | `agent\edge_agent.py` | مراقبة ملفات |
| الواجهة | HTML/JS | `frontend` | عرض |
| الإعداد | Python | `config.py` | وضع وإطار |
| الحاويات | Docker | `Dockerfile` | تشغيل |

## Quick Start

```
cd Guardian-X
pip install -r requirements.txt
python server\train_models.py
python server\app.py
```

ثم فتح `http://127.0.0.1:5000`.

## For Non-Technical Users

النظام يراقب نشاط الملفات على جهاز ويظهر في صفحة ويب إن كان السلوك بعيدا عن المعتاد. يمكنه عرض تنبيه وتفسير مبسط وتسجيل إجراء. التشغيل الحالي معد للمحاكاة. ملفات الجداول الكبيرة بيانات تدريب محلية وليست شاشة للمستخدم.

## For Developers

- التقنيات: Python و Flask و SQLite و scikit-learn و LightGBM و SHAP و LIME.
- المعمارية: وكيل، خادم، لوحة، ملف SQLite.
- القاعدة: `guardian.db` والجداول الستة أعلاه.
- الواجهة: مسارات القسم 22.
- ملفات البداية: `app.py`, `db.py`, `rules.py`, `ml_models.py`, `edge_agent.py`, `config.py`.
- التطوير: أضف المسار في `app.py` والجدول في `init_db` ثم حدّث `frontend\script.js`.
