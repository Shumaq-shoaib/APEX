export interface ApiMetadata {
    api_title: string;
    api_version: string;
    file_analyzed?: string;
    timestamp_utc: string;
    server_url?: string;
    profile_used?: string;
}

export interface ApiSummary {
    total: number;
    Critical?: number;
    High?: number;
    Medium?: number;
    Low?: number;
    Informational?: number;
    [key: string]: number | undefined;
}

export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Informational" | "Info";

export interface FindingEvidence {
    examples?: string[];
    [key: string]: unknown;
}

export interface StaticVulnerability {
    id: string;
    rule_key?: string;
    name: string;
    severity: SeverityLevel;
    description?: string;
    details?: {
        description?: string;
        [key: string]: unknown;
    };
    recommendation?: string;
    owasp_ref?: string;
    severity_score?: number;
    evidence?: FindingEvidence;
}

export interface EndpointFindings {
    path: string;
    method?: string;
    vulnerabilities: StaticVulnerability[];
}

export interface DynamicEvidence {
    request_dump?: string;
    response_dump?: string;
}

export interface Finding {
    id: string;
    title: string;
    description: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info" | "Informational";
    category?: string;
    cwe?: string;
    remediation?: string;
    method?: string;
    endpoint_path?: string;
    test_case_id?: string;
    cvss_score?: number | string;
    check_type?: string;
    evidence?: DynamicEvidence;
}

export interface AnalysisData {
    spec_id: string;
    metadata: ApiMetadata;
    summary: ApiSummary;
    endpoints: EndpointFindings[];
    dynamic_session_id?: string | null;
}

export interface DynamicSession {
    id: string;
    status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
    test_cases: TestCase[];
    findings: Finding[];
    error_message?: string;
}

export interface TestCase {
    id: string;
    check_type: string;
    endpoint_path: string;
    method: string;
    status: "PENDING" | "QUEUED" | "EXECUTED" | "SKIPPED" | "FAILED";
    logs?: string;
}
