# -*- coding: utf-8 -*-
import os
import yaml
import logging
from typing import Dict, Any, Set, List
from datetime import timezone

UTC_TZ = timezone.utc

# --- Default Config ---
CONFIG: Dict[str, Any] = {
    "unsafe_verbs_i18n": {
        "create": ["create","crear","créer","создать","بنائیں","创建"],
        "delete": ["delete","eliminar","supprimer","удалить","حذف","删除"],
        "update": ["update","actualizar","mettre à jour","обновить","اپڈیٹ","更新"],
        "assign": ["assign","asignar","attribuer","назначить","تقرری","分配"],
        "activate": ["activate","activar","activer","активировать","فعال کریں","激活"],
        "reset": ["reset","restablecer","réinitialiser","сбросить","ری سیٹ","重置"],
        "provision": ["provision","aprovisionar","provisionner","подготовить","فراہم کریں","配置"],
        "upload": ["upload","subir","téléverser","загрузить","اپ لوڈ","上传"],
        "generate": ["generate","generar","générer","сгенерировать","جنریٹ","生成"]
    },
    "sensitive_keywords": {
        "password","token","secret","apikey","api_key","auth","authorization",
        "creditcard","cc_number","ssn","social_security_number","private_key",
        "refresh_token","access_token","pin","cvv","otp","image_url","avatar_url"
    },
    "sensitive_id_keywords": {
        "id","userid","accountid","customerid","orderid","profileid",
        "deviceid","sessionid","orgid","tenantid","projectid","invoiceid","cardid"
    },
    "required_security_headers": {
        "content-security-policy","strict-transport-security",
        "x-content-type-options","x-frame-options","referrer-policy",
        "cross-origin-opener-policy"
    },
    # Documentation hints toggles
    "enable_doc_hint_rate_limit_headers": True,
    "enable_doc_hint_security_headers": True,

    # Scope markers
    "privileged_scope_markers": {"admin","root","super","manage","write","all","owner","moderate"},
    "broad_scope_markers": {"public","guest","basic","user","read","openid","email","profile"},

    # Vendor extension keys
    "vendor_scope_keys": ["x-scope","x-scopes","x-role","x-roles"],
    "vendor_sensitive_keys": ["x-sensitive","x-internal"],

    # JSON-ish media types
    "json_media_types": ["application/json", "application/*+json"],

    # URL-like field hints for SSRF scanning
    "url_field_hints": {"url","uri","endpoint","redirect","callback","webhook","target","link","image_url","avatar_url"},

    # Policy overrides / toggles
    "override_severity": {},        # {check_key: "Critical|High|Medium|Low"}
    "disable_rules": set(),         # {check_key}
    
    # Performance knobs
    "max_example_bytes": 2 * 1024 * 1024,  # 2MB guardrail for examples
    "parallel_checks": True,               # enable per-endpoint parallel map
    "threads": 8,                          # default thread pool size when enabled
    "allowed_remote_ref_domains": [],      # keep empty to block by default
    "max_ref_depth": 32,
}

def load_config(file_path: str) -> None:
    global CONFIG
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                custom = yaml.safe_load(f) or {}
            for k, v in custom.items():
                if isinstance(v, (list, set)) and k in CONFIG:
                    CONFIG[k] = set(CONFIG[k]) | set(v)
                else:
                    CONFIG[k] = v
            logging.info(f"Loaded custom configuration from {file_path}")
        except Exception as e:
            logging.error(f"Failed to load custom configuration: {e}")

# --- Severity buckets (normalized) ---
SEVERITY_SCORES = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
