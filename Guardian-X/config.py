# -*- coding: utf-8 -*-
# --- إطار الأمن (توثيق وتطبيق داخل الكود) ---
# NIST Cybersecurity Framework 2.0 + تعيين مؤشر لـ ISO/IEC 27001:2022 (Annex A)
# تفاصيل الضوابط: GET /api/security/framework
SECURITY_FRAMEWORK = "NIST_CSF_2.0"
ISO_27001_MAPPING_ENABLED = True

# --- وضع التشغيل ---
# 'simulation' = محاكاة كاملة بدون هاردوير
# 'hybrid' = وكلاء محاكاة + وكلاء فعلية
# 'hardware' = وكلاء هاردوير فقط (Raspberry Pi, Mini-PC)
MODE = 'simulation'

# --- إعدادات الربط بالهاردوير (للاستخدام المستقبلي) ---
HARDWARE = {
    # Raspberry Pi / Mini-PC
    'supported_platforms': ['raspberry_pi', 'mini_pc', 'linux', 'windows'],
    # عنوان السيرفر المركزي (يُعدّل عند النشر)
    'server_url': 'https://127.0.0.1:5000',
    # TLS: ضع الشهادات في server/certs/ وشغّل السيرفر — يُفضّل TLS 1.3 عند دعم Python/OpenSSL
    'use_tls': True,
    'tls_cert_path': 'server/certs/cert.pem',
    # تشغيل ML محلي على الوكيل (مستقبلاً - التقرير: local Isolation Forest)
    'local_ml_on_edge': False,
    'local_model_path': None,
    # إرسال agent_id تلقائياً عند الربط
    'auto_register_agent': True,
}

# --- حدود المعاملات (من التقرير) ---
TRANSACTION_THRESHOLDS = {
    'suspicious_amount': 10000,
    'high_risk_amount': 50000,
}
