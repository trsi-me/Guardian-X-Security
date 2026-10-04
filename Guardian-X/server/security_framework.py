# -*- coding: utf-8 -*-
# NIST CSF 2.0 + تعيين مؤشر ISO/IEC 27001 Annex A — مرجع: nist.gov/cyberframework ، iso.org/standard/27001
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# الإطار النشط في التشغيل (يُقرأ من config إن وُجد)
DEFAULT_FRAMEWORK = "NIST_CSF_2.0"


@dataclass
class ControlMapping:
    nist_function: str  # GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
    nist_category: str
    iso27001_annex_a: List[str]
    guardian_implementation: str
    status: str = "implemented"  # implemented | partial | planned


# خريطة التنفيذ داخل المنتج (مرتبطة بالكود الفعلي)
GUARDIAN_CONTROL_MAP: List[ControlMapping] = [
    ControlMapping(
        "PROTECT",
        "PR.DS Data Security",
        ["A.8.11", "A.8.12"],
        "تشفير الاتصال TLS 1.2+ (استهداف TLS 1.3) عبر Flask؛ شهادات في server/certs/",
    ),
    ControlMapping(
        "DETECT",
        "DE.CM Continuous Monitoring",
        ["A.8.16", "A.5.24"],
        "Edge Agent + مراقبة أحداث الملفات والمعاملات في الوقت الفعلي (watchdog / API)",
    ),
    ControlMapping(
        "DETECT",
        "DE.AE Anomalies and Events",
        ["A.8.16"],
        "كشف شذوذ سلوكي: قواعد + تعلم آلي (Isolation Forest, LightGBM, Autoencoder) + XAI",
    ),
    ControlMapping(
        "RESPOND",
        "RS.MI Incident Management",
        ["A.5.24", "A.5.26"],
        "تنبيهات، تسجيل MTTD/MTTR، إجراءات احتواء محاكاة (block, isolate, freeze)",
    ),
    ControlMapping(
        "IDENTIFY",
        "ID.AM Asset Management",
        ["A.5.9", "A.8.1"],
        "تسجيل الوكلاء (agents) ومسارات الملفات وأنشطة المستخدمين",
    ),
    ControlMapping(
        "GOVERN",
        "GV.RM Risk Management",
        ["A.5.1", "A.5.2"],
        "ملف سلوك متكيف (behavior_profile) وعتبات مخاطرة قابلة للتعديل",
    ),
    ControlMapping(
        "PROTECT",
        "PR.AA Identity Management / Authentication",
        ["A.5.15", "A.5.16"],
        "مراقبة محاولات تسجيل الدخول (login_monitor) لاكتشاف إساءة استخدام الحسابات",
    ),
]


def get_framework_summary(
    active_framework: Optional[str] = None,
    tls_enabled: bool = False,
) -> Dict[str, Any]:
    fw = active_framework or DEFAULT_FRAMEWORK
    controls = []
    for c in GUARDIAN_CONTROL_MAP:
        controls.append(
            {
                "nist_function": c.nist_function,
                "nist_category": c.nist_category,
                "iso27001_annex_a": c.iso27001_annex_a,
                "guardian_implementation": c.guardian_implementation,
                "status": c.status,
            }
        )
    return {
        "primary_framework": fw,
        "aligned_standards": [
            "NIST Cybersecurity Framework 2.0",
            "ISO/IEC 27001:2022 (Annex A mapping — indicative)",
        ],
        "references": {
            "nist_csf": "https://www.nist.gov/cyberframework",
            "iso27001": "https://www.iso.org/standard/27001",
        },
        "transport_security": {
            "target": "TLS 1.3",
            "minimum_configured": "TLS 1.2+",
            "https_active": tls_enabled,
        },
        "controls_mapped": len(controls),
        "controls": controls,
    }
