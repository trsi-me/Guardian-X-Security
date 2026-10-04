# -*- coding: utf-8 -*-
from datetime import datetime

SENSITIVE_EXTENSIONS = ['.ini', '.config', '.env', '.key', '.pem', '.crt', '.xml','.exe', '.dll', '.sys', '.bat', '.ps1']
SENSITIVE_DOWNLOADS = ['customer_data', 'confidential', 'secret', '.zip', '.xlsx', 'backup']
TRANSACTION_HIGH_RISK_AMOUNT = 50000
TRANSACTION_SUSPICIOUS_AMOUNT = 10000

def _parse_transaction_amount(file_path):
    # المبلغ: أول جزء رقمي بعد النوع (مثل transfer:5000 أو wire:12000.50:mobile:3)
    if not file_path or ':' not in file_path:
        return 0
    parts = file_path.split(':')
    for p in parts[1:]:
        try:
            return float(p)
        except ValueError:
            continue
    return 0


def _parse_transaction_velocity(file_path):
    # الحقل الرابع (إن وُجد): سرعة/عدد في نافذة ~10 دقائق للبيانات الاصطناعية
    parts = (file_path or '').split(':')
    if len(parts) >= 4:
        try:
            return int(float(parts[3]))
        except ValueError:
            pass
    return 0


UNAUTHORIZED_COPY_DEST = (
    'usb', 'exfil', 'unauth', '/mnt/usb', 'usb_stick', 'public/unauth',
    'users/public', 'removable'
)


def rule_unauthorized_file_copy(activity_type, file_path):
    if activity_type != 'FileCopy':
        return False
    raw = file_path or ''
    if '|' not in raw:
        return False
    src, dst = raw.split('|', 1)
    s_low, d_low = src.lower(), dst.lower()
    sensitive_src = is_sensitive_file(src) or any(
        m in s_low for m in ('customer_pii', 'vault/', 'salaries', 'signing_key', 'ledger_gl', 'confidential')
    )
    bad_dest = any(m in d_low for m in UNAUTHORIZED_COPY_DEST)
    return sensitive_src and bad_dest

def is_within_work_hours(timestamp, work_start='08:00', work_end='17:00'):
    try:
        if isinstance(timestamp, str):
            dt = datetime.strptime(timestamp[:19], '%Y-%m-%d %H:%M:%S')
        else:
            dt = timestamp
        t = dt.time()
        start = datetime.strptime(work_start, '%H:%M').time()
        end = datetime.strptime(work_end, '%H:%M').time()
        return start <= t <= end
    except Exception:
        return True

def is_sensitive_file(file_path):
    path_lower = file_path.lower()
    return any(path_lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS)

def rule_excessive_deletion(delete_count, threshold=5, time_window_minutes=10):
    return delete_count > threshold

def rule_repeated_access(access_count, time_window_minutes=1, threshold=5):
    return access_count >= threshold

def rule_outside_work_hours(timestamp, work_start, work_end):
    return not is_within_work_hours(timestamp, work_start, work_end)

def rule_sensitive_modification(activity_type, file_path):
    return activity_type == 'Modify' and is_sensitive_file(file_path)

def rule_sensitive_download(file_path):
    path_lower = (file_path or '').lower()
    return any(s in path_lower for s in SENSITIVE_DOWNLOADS)

SYSTEM_PATHS = [
    'windows/system32',
    'windows/syswow64',
    'system32/config/sam',
    'system32/drivers/etc/hosts',
    'winevt/logs',
    'system32/config/system',
    'program files',
]

def rule_system_path(file_path):
    path_lower = (file_path or '').lower().replace('\\', '/')
    return any(s in path_lower for s in SYSTEM_PATHS)

def apply_rules(activity_type, file_path, timestamp, context, profile):
    reasons = []
    risk_level = 'Normal'

    work_start = profile.get('work_start_time', '08:00')
    work_end = profile.get('work_end_time', '17:00')

    if rule_outside_work_hours(timestamp, work_start, work_end):
        if activity_type == 'Delete':
            risk_level = 'High Risk'
            reasons.append('File deletion outside working hours')
        elif activity_type in ['Modify', 'FileDownload', 'FileCopy']:
            if risk_level == 'Normal':
                risk_level = 'Suspicious'
            reasons.append('Activity outside working hours')

    if rule_system_path(file_path):
        if file_path.lower().endswith(('.exe', '.dll', '.sys', '.bat', '.ps1')):
            risk_level = 'High Risk'
            reasons.append('Executable file in system directory — possible malware installation')
        elif activity_type in ['Create', 'Modify', 'Delete']:
            if risk_level == 'Normal':
                risk_level = 'Suspicious'
            reasons.append('Activity in system directory — possible tampering')
    
    # Executable creation anywhere = suspicious
    if activity_type == 'Create' and file_path.lower().endswith('.exe'):
        if risk_level == 'Normal':
            risk_level = 'Suspicious'
        reasons.append('Executable file created — verify this is legitimate software')

    if rule_sensitive_modification(activity_type, file_path):
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append('Modification of sensitive file')

    if context.get('delete_count_10min', 0) > profile.get('normal_delete_limit', 3):
        risk_level = 'High Risk'
        reasons.append(f'Excessive deletions (>{profile.get("normal_delete_limit", 3)} in 10 min)')

    if context.get('modify_count_hour', 0) > profile.get('normal_modify_limit', 5):
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append(f'Excessive modifications (>{profile.get("normal_modify_limit", 5)}/hour)')

    if context.get('same_file_access_count', 0) >= 3:
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append('Excessive file access frequency')

    # قواعد المعاملات المالية (محاكاة + بيانات مصرفية اصطناعية)
    if activity_type == 'Transaction':
        amount = _parse_transaction_amount(file_path)
        vel = _parse_transaction_velocity(file_path)
        if amount >= TRANSACTION_HIGH_RISK_AMOUNT and rule_outside_work_hours(timestamp, work_start, work_end):
            risk_level = 'High Risk'
            reasons.append(f'Large transaction ({amount:,.0f}) outside working hours')
        elif amount >= TRANSACTION_HIGH_RISK_AMOUNT:
            if risk_level != 'High Risk':
                risk_level = 'Suspicious'
            reasons.append(f'Unusually large transaction ({amount:,.0f})')
        elif amount >= TRANSACTION_SUSPICIOUS_AMOUNT:
            if risk_level != 'High Risk':
                risk_level = 'Suspicious'
            reasons.append(f'Transaction amount above threshold ({amount:,.0f})')
        if context.get('transaction_count_10min', 0) >= 5 or vel >= 6:
            if risk_level != 'High Risk':
                risk_level = 'Suspicious'
            reasons.append('Multiple rapid transactions / high velocity (10m window)')

    # نسخ ملفات حساسة إلى وجهة غير مصرح بها (انسخ بدون إذن)
    if rule_unauthorized_file_copy(activity_type, file_path):
        risk_level = 'High Risk'
        reasons.append('Unauthorized copy of sensitive data to external/untrusted path')

    # قواعد تحميل الملفات (محاكاة)
    if activity_type == 'FileDownload' and rule_sensitive_download(file_path):
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append('Download of sensitive/confidential file')
    if activity_type == 'FileDownload' and rule_outside_work_hours(timestamp, work_start, work_end):
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append('File download outside working hours')

    if activity_type == 'FileCopy' and rule_outside_work_hours(timestamp, work_start, work_end):
        if risk_level != 'High Risk':
            risk_level = 'Suspicious'
        reasons.append('File copy outside working hours')

    reason = '; '.join(reasons) if reasons else 'Normal activity'
    return risk_level, reason
