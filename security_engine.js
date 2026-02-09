/* =========================================================
   SECURITY ENGINE – CUSTOM HEURISTIC SCANNER
   ========================================================= */

/* -----------------------------
   CONFIG
----------------------------- */

const MALICIOUS_KEYWORDS = [
  "free-money",
  "crypto",
  "wallet",
  "airdrop",
  "hack",
  "keygen",
  "crack",
  "stealer",
  "trojan",
  "virus",
  "malware",
  "login",
  "verify",
  "update-now",
  "secure-now"
];

/* -----------------------------
   CSV STORAGE
----------------------------- */

let maliciousCsvEntries = [];

/* -----------------------------
   LOAD CSV (call once on app start)
----------------------------- */

async function loadMaliciousCsv() {
  try {
    const response = await fetch("malicious_phish.csv");
    const text = await response.text();

    maliciousCsvEntries = text
      .split("\n")
      .map(line => line.trim().toLowerCase())
      .filter(Boolean);

    console.info("[Security] Malicious CSV loaded:", maliciousCsvEntries.length);
  } catch (err) {
    console.warn("[Security] Failed to load CSV:", err);
  }
}

/* -----------------------------
   HELPER FUNCTIONS
----------------------------- */

function containsMaliciousKeyword(value) {
  const lower = value.toLowerCase();
  return MALICIOUS_KEYWORDS.some(keyword => lower.includes(keyword));
}

function existsInCsv(value) {
  const lower = value.toLowerCase();
  return maliciousCsvEntries.some(entry => lower.includes(entry));
}

/* -----------------------------
   LINK ANALYSIS
----------------------------- */

function analyzeLink(url) {
  if (!url) {
    return { dangerous: false, reason: "Empty URL" };
  }

  if (containsMaliciousKeyword(url)) {
    return {
      dangerous: true,
      reason: "Malicious keyword detected in URL"
    };
  }

  if (existsInCsv(url)) {
    return {
      dangerous: true,
      reason: "URL found in malicious database"
    };
  }

  return {
    dangerous: false,
    reason: "URL is safe"
  };
}

/* -----------------------------
   FILE ANALYSIS
----------------------------- */

function analyzeFile(file) {
  if (!file || !file.name) {
    return { dangerous: false, reason: "Invalid file" };
  }

  const filename = file.name.toLowerCase();

  if (filename.endsWith(".exe")) {
    return {
      dangerous: true,
      reason: "Executable (.exe) files are blocked"
    };
  }

  if (containsMaliciousKeyword(filename)) {
    return {
      dangerous: true,
      reason: "Malicious keyword detected in filename"
    };
  }

  if (existsInCsv(filename)) {
    return {
      dangerous: true,
      reason: "Filename found in malicious database"
    };
  }

  return {
    dangerous: false,
    reason: "File is safe"
  };
}

/* -----------------------------
   MESSAGE SCAN (TEXT + LINKS)
----------------------------- */

function analyzeMessage(messageText) {
  if (!messageText) {
    return { dangerous: false, reason: "Empty message" };
  }

  const urls = messageText.match(/https?:\/\/[^\s]+/gi);

  if (!urls) {
    return { dangerous: false, reason: "No links found" };
  }

  for (const url of urls) {
    const result = analyzeLink(url);
    if (result.dangerous) {
      return {
        dangerous: true,
        reason: result.reason,
        value: url
      };
    }
  }

  return {
    dangerous: false,
    reason: "Message is safe"
  };
}

/* -----------------------------
   PUBLIC API (what you call)
----------------------------- */

window.SecurityEngine = {
  loadMaliciousCsv,
  analyzeLink,
  analyzeFile,
  analyzeMessage
};
