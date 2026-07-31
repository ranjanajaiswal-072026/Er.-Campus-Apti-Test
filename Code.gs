/**
 * InCred Campus Aptitude Test — Secure Backend (v5)
 * ==================================================
 * Single deployment. Two surfaces:
 *   Student / Landing → https://.../exec
 *   HR Admin Portal   → https://.../exec?view=admin
 *
 * Sheet tabs required (exact names):
 *   Responses | Login Attempts | Retry Approvals | HR Users
 *
 * HR Users tab columns: Email | Name | Role (Admin / Viewer)
 *
 * See SETUP INSTRUCTIONS at bottom.
 */

// ── Constants ────────────────────────────────────────────────────────
const SHEET_NAME           = "Responses";
const LOGIN_LOG_SHEET_NAME = "Login Attempts";
const RETRY_SHEET_NAME     = "Retry Approvals";
const HR_USERS_SHEET_NAME  = "HR Users";
const DIGEST_RECIPIENT     = "ranjana.jaiswal@incred.com";

const SESSION_TTL_SECONDS  = 70 * 60;   // session cache TTL (slightly > test duration)
const TEST_DURATION_SECONDS= 60 * 60;
const PERCENTILE_CUTOFF    = 75;

const OTP_VALIDITY_MS      = 10 * 60 * 1000;   // 10 minutes
const HR_SESSION_DURATION_MS = 30 * 60 * 1000; // 30 minutes

const MARKS_CORRECT = 3;
const MARKS_WRONG   = -1;
const Q9_MAX        = 5;
const Q10_MAX       = 8;

// ── Pipeline status labels ────────────────────────────────────────────
const STATUS_NOT_QUALIFIED_TEST  = "Not Qualified in Test";
const STATUS_SHORTLISTED_R1      = "Shortlisted for PI Round 1";
const STATUS_NOT_QUALIFIED_R1    = "Not Qualified in PI Round 1";
const STATUS_SHORTLISTED_R2      = "Shortlisted for PI Round 2";
const STATUS_NOT_QUALIFIED_R2    = "Not Qualified in PI Round 2";
const STATUS_SELECTED            = "Selected";

// ── doGet — dual-URL router ──────────────────────────────────────────
function doGet(e) {
  const action   = (e.parameter.action || "").trim();
  const viewMode = (e.parameter.view   || "").toLowerCase();

  if (viewMode === "admin") {
    return HtmlService.createHtmlOutputFromFile("HRAdmin")
      .setTitle("InCred Finance — HR Admin Portal")
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  }

  // Student API
  if (action === "checkRoll") {
    const roll = (e.parameter.roll || "").trim();
    return jsonOutput({ exists: rollNumberExists(roll) });
  }

  if (action === "startSession") {
    return handleStartSession(e);
  }

  // Default: serve landing + student page
  return HtmlService.createHtmlOutputFromFile("Index")
    .setTitle("InCred Finance — Campus Recruitment")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

// ── doPost — routes to student submission OR HR admin actions ─────────
function doPost(e) {
  let session = null;
  try {
    const data = JSON.parse(e.postData.contents);

    // HR OTP request
    if (data.hrAction === "requestOTP")  return handleRequestOTP(data);
    if (data.hrAction === "verifyOTP")   return handleVerifyOTP(data);

    // HR admin actions (require valid hr session token)
    if (data.adminAction) return handleAdminAction(data);

    // Student submission
    return handleStudentSubmission(data, session);

  } catch (err) {
    logLoginAttempt("", "", "Error", "Script Error in doPost", err.message);
    return jsonOutput({ status: "error", message: err.message });
  }
}

// ════════════════════════════════════════════════════════════════════
// HR OTP AUTHENTICATION
// ════════════════════════════════════════════════════════════════════
function handleRequestOTP(data) {
  const email = (data.email || "").trim().toLowerCase();
  if (!email) return jsonOutput({ status: "error", message: "Email is required." });

  const hrUser = findHRUser(email);
  if (!hrUser) {
    logLoginAttempt("", email, "HR OTP Request", "Email Not Registered", "");
    return jsonOutput({ status: "not_registered" });
  }

  // Generate 6-digit OTP, replace any existing one
  const otp       = String(Math.floor(100000 + Math.random() * 900000));
  const otpKey    = "otp_" + email.replace(/[^a-z0-9]/g, "_");
  const cache     = CacheService.getScriptCache();
  cache.put(otpKey, JSON.stringify({ otp, expiry: Date.now() + OTP_VALIDITY_MS }), 600);

  // Send OTP email
  const body = `
Dear ${hrUser.name},

Your one-time password (OTP) for the InCred Finance Campus Recruitment HR Portal is:

    ${otp}

This OTP is valid for 10 minutes. Do not share it with anyone.

If you did not request this, please ignore this email.

— InCred Finance HR Team
  `.trim();

  MailApp.sendEmail({
    to      : hrUser.email,
    subject : "InCred Campus Portal — Your OTP",
    body    : body
  });

  logLoginAttempt(hrUser.name, email, "HR OTP Request", "OTP Sent", "");
  return jsonOutput({ status: "ok" });
}

function handleVerifyOTP(data) {
  const email    = (data.email || "").trim().toLowerCase();
  const entered  = (data.otp   || "").trim();
  if (!email || !entered) return jsonOutput({ status: "error", message: "Email and OTP required." });

  const hrUser = findHRUser(email);
  if (!hrUser) return jsonOutput({ status: "not_registered" });

  const cache  = CacheService.getScriptCache();
  const otpKey = "otp_" + email.replace(/[^a-z0-9]/g, "_");
  const raw    = cache.get(otpKey);

  if (!raw) return jsonOutput({ status: "otp_expired" });

  const stored = JSON.parse(raw);
  if (Date.now() > stored.expiry)  { cache.remove(otpKey); return jsonOutput({ status: "otp_expired" }); }
  if (entered !== stored.otp)       return jsonOutput({ status: "otp_invalid" });

  // OTP correct — issue HR session token
  cache.remove(otpKey);
  const hrToken   = Utilities.getUuid();
  const sessionKey= "hrsess_" + hrToken;
  cache.put(sessionKey, JSON.stringify({
    email   : hrUser.email,
    name    : hrUser.name,
    role    : hrUser.role,
    expiry  : Date.now() + HR_SESSION_DURATION_MS
  }), Math.ceil(HR_SESSION_DURATION_MS / 1000) + 60);

  logLoginAttempt(hrUser.name, email, "HR Login", "Success", `Role=${hrUser.role}`);
  return jsonOutput({ status: "ok", hrToken, name: hrUser.name, role: hrUser.role });
}

function validateHRSession(hrToken) {
  if (!hrToken) return null;
  const cache      = CacheService.getScriptCache();
  const sessionKey = "hrsess_" + hrToken;
  const raw        = cache.get(sessionKey);
  if (!raw) return null;
  const sess = JSON.parse(raw);
  if (Date.now() > sess.expiry) { cache.remove(sessionKey); return null; }
  return sess;
}

function findHRUser(email) {
  try {
    const sheet   = getHRUsersSheet();
    const lastRow = sheet.getLastRow();
    if (lastRow < 2) return null;
    const data = sheet.getRange(2, 1, lastRow - 1, 3).getValues();
    for (const row of data) {
      if (String(row[0]).trim().toLowerCase() === email) {
        return { email: String(row[0]).trim(), name: String(row[1]).trim(), role: String(row[2]).trim() || "Viewer" };
      }
    }
  } catch (e) {}
  return null;
}

// ════════════════════════════════════════════════════════════════════
// HR ADMIN ACTIONS
// ════════════════════════════════════════════════════════════════════
function handleAdminAction(data) {
  const sess = validateHRSession(data.hrToken);
  if (!sess) return jsonOutput({ status: "session_expired" });

  const isAdmin = sess.role === "Admin";

  if (data.adminAction === "getCandidates") {
    const sheet   = getSheet();
    const lastRow = sheet.getLastRow();
    if (lastRow < 2) return jsonOutput({ status: "ok", candidates: [] });
    const rows = sheet.getRange(2, 1, lastRow - 1, 59).getValues();
    const candidates = rows.map((row, i) => ({
      rowIndex       : i + 2,
      name           : row[1],
      roll           : row[2],
      status         : row[5],
      timeTaken      : row[6],
      remarks        : row[7],
      section1Score  : row[48],
      codingScore    : row[49],
      totalScore     : row[50],
      retryAttempt   : row[51],
      percentile     : row[52],
      testPipelineStatus : row[53],  // col 54: pipeline status (test stage)
      override       : row[54] || "AUTO",
      round1Status   : row[55] || "",
      round1Feedback : row[56] || "",
      round2Status   : row[57] || "",
      round2Feedback : row[58] || ""
    }));
    return jsonOutput({ status: "ok", candidates, role: sess.role, name: sess.name });
  }

  // All write actions require Admin role
  if (!isAdmin) return jsonOutput({ status: "forbidden", message: "Viewer role cannot edit records." });

  if (data.adminAction === "updateCandidate") {
    const sheet  = getSheet();
    const rowIdx = parseInt(data.rowIndex, 10);
    if (isNaN(rowIdx) || rowIdx < 2) return jsonOutput({ status: "error", message: "Invalid row index." });
    // Col 55=override, 56=R1 Status, 57=R1 Feedback, 58=R2 Status, 59=R2 Feedback
    if (data.override       !== undefined) sheet.getRange(rowIdx, 55).setValue(data.override);
    if (data.round1Status   !== undefined) sheet.getRange(rowIdx, 56).setValue(data.round1Status);
    if (data.round1Feedback !== undefined) sheet.getRange(rowIdx, 57).setValue(data.round1Feedback);
    if (data.round2Status   !== undefined) sheet.getRange(rowIdx, 58).setValue(data.round2Status);
    if (data.round2Feedback !== undefined) sheet.getRange(rowIdx, 59).setValue(data.round2Feedback);
    return jsonOutput({ status: "ok" });
  }

  if (data.adminAction === "exportReport") {
    return buildExportData(data.stage);
  }

  return jsonOutput({ status: "error", message: "Unknown adminAction." });
}

function buildExportData(stage) {
  const sheet   = getSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return jsonOutput({ status: "ok", rows: [], headers: [] });

  const allRows = sheet.getRange(2, 1, lastRow - 1, 59).getValues();
  let headers, rows = [];

  if (stage === "TEST") {
    headers = ["Name", "Roll Number", "Test Status", "Total Score", "Percentile", "Override", "Remarks"];
    allRows.forEach(row => {
      if (row[5] === "DISQUALIFIED") return;
      rows.push([row[1], row[2], row[53] || "", row[50], row[52] !== "" ? row[52] + "%" : "", row[54] || "AUTO", row[7]]);
    });
  } else if (stage === "ROUND1") {
    headers = ["Name", "Roll Number", "Total Score", "Percentile", "Round 1 Status", "Round 1 Feedback"];
    allRows.forEach(row => {
      const override = row[54] || "AUTO";
      const selected = row[53];
      if ((selected === STATUS_SHORTLISTED_R1 || override === "INCLUDE") && override !== "EXCLUDE") {
        rows.push([row[1], row[2], row[50], row[52] !== "" ? row[52] + "%" : "", row[55] || "Pending", row[56] || ""]);
      }
    });
  } else if (stage === "ROUND2") {
    headers = ["Name", "Roll Number", "Total Score", "Percentile", "Round 1 Feedback", "Round 2 Status", "Round 2 Feedback"];
    allRows.forEach(row => {
      if (row[55] === STATUS_SHORTLISTED_R2) {
        rows.push([row[1], row[2], row[50], row[52] !== "" ? row[52] + "%" : "", row[56] || "", row[57] || "Pending", row[58] || ""]);
      }
    });
  }

  return jsonOutput({ status: "ok", headers, rows });
}

// ════════════════════════════════════════════════════════════════════
// STUDENT SESSION & SUBMISSION
// ════════════════════════════════════════════════════════════════════
function handleStartSession(e) {
  const roll = (e.parameter.roll || "").trim();
  const name = (e.parameter.name || "").trim();
  let excludePrev = null, isRetry = false;

  if (rollNumberExists(roll)) {
    const approval = findUnusedRetryApproval(roll);
    if (!approval) {
      logLoginAttempt(name, roll, "Start Attempt", "Duplicate - Blocked", "");
      return jsonOutput({ status: "duplicate" });
    }
    markRetryUsed(approval.rowIndex);
    excludePrev = getPreviousSets(roll);
    isRetry     = true;
  }

  const assigned        = assignSets(excludePrev);
  const token           = Utilities.getUuid();
  const startTime       = Date.now();
  const sessionDuration = isRetry
    ? getRemainingSecondsFromLastDisqualification(roll)
    : TEST_DURATION_SECONDS;

  const cache = CacheService.getScriptCache();
  cache.put(token, JSON.stringify({
    roll, name, set1: assigned.set1, set2: assigned.set2,
    startTime, isRetry, sessionDuration
  }), SESSION_TTL_SECONDS);

  logLoginAttempt(name, roll, "Start Attempt",
    isRetry ? "OK - Retry Granted" : "OK - New Session",
    `Set1=${assigned.set1}, Set2=${assigned.set2}, Duration=${sessionDuration}s`);

  return jsonOutput({
    status             : "ok",
    token,
    testDurationSeconds: sessionDuration,
    section1           : sanitizeSection1(SECTION1_SETS[assigned.set1]),
    section2           : sanitizeSection2(SECTION2_SETS[assigned.set2])
  });
}

function handleStudentSubmission(data, sessionRef) {
  const token    = data.token;
  const cache    = CacheService.getScriptCache();
  const rawSess  = cache.get(token);

  if (!rawSess) {
    logLoginAttempt("", "", "Submission Error", "Invalid/Expired Session", "");
    return jsonOutput({ status: "invalid_session" });
  }
  const session = JSON.parse(rawSess);
  const roll    = session.roll;

  if (rollNumberExists(roll) && !session.isRetry) {
    cache.remove(token);
    logLoginAttempt(session.name, roll, "Submission Error", "Duplicate at Submission", "");
    return jsonOutput({ status: "duplicate" });
  }

  const set1Questions = SECTION1_SETS[session.set1];
  const set2Data      = SECTION2_SETS[session.set2];

  const section1Results = set1Questions.map((question, idx) => {
    const submitted = data.section1Answers ? data.section1Answers[idx] : null;
    const correctText = question.o[question.correctIndex];
    let points, label, submittedText;
    if (submitted === null || submitted === undefined) {
      label = "UNANSWERED"; points = 0; submittedText = "Not Answered";
    } else if (submitted === question.correctIndex) {
      label = "CORRECT"; points = MARKS_CORRECT; submittedText = question.o[submitted];
    } else {
      label = "INCORRECT"; points = MARKS_WRONG; submittedText = question.o[submitted] || "Invalid";
    }
    return { questionText: question.q, submittedText, correctText, points, label };
  });

  const section1Score    = section1Results.reduce((s, r) => s + r.points, 0);
  const unansweredCount  = section1Results.filter(r => r.label === "UNANSWERED").length;
  const correctCount     = section1Results.filter(r => r.label === "CORRECT").length;
  const q9Answer         = (data.q9Answer  || "").trim();
  const q10Answer        = (data.q10Answer || "").trim();
  const q9Score          = scoreQ9(q9Answer);
  const q10Score         = scoreQ10(q10Answer);
  const totalScore       = section1Score + q9Score + q10Score;
  const timeTakenSeconds = Math.max(0, Math.round((Date.now() - session.startTime) / 1000));
  const status           = data.status || "Completed";
  const remarks          = buildRemarks(status, unansweredCount, correctCount, timeTakenSeconds);

  const sheet = getSheet();
  const row = [
    new Date(), session.name, roll, session.set1, session.set2,
    status, formatTime(timeTakenSeconds), remarks
  ];
  section1Results.forEach(r => row.push(r.questionText, r.submittedText, r.correctText, r.points));
  row.push(set2Data.q9.text, q9Answer || "Not Answered", q9Score, Q9_MAX);
  row.push(buildQ10QuestionText(), q10Answer || "Not Answered", q10Score, Q10_MAX);
  row.push(section1Score, q9Score + q10Score, totalScore);
  row.push(session.isRetry ? "Yes" : "No");
  // Col 53: pipeline test status (blank initially, filled by recalculatePercentiles)
  // Col 54: override, Cols 55-59: pipeline fields — all blank at submission
  row.push("", "AUTO", "", "", "", "");

  sheet.appendRow(row);
  cache.remove(token);
  recalculatePercentiles();

  return jsonOutput({ status: "success" });
}

// ════════════════════════════════════════════════════════════════════
// PERCENTILE + PIPELINE TEST STATUS
// ════════════════════════════════════════════════════════════════════
function recalculatePercentiles() {
  const sheet   = getSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return;

  const data             = sheet.getRange(2, 1, lastRow - 1, 59).getValues();
  const statusColIdx     = 5;   // col F: test submission status
  const totalScoreColIdx = 50;  // col AQ

  const eligibleScores = data
    .filter(row => row[statusColIdx] === "Completed" || row[statusColIdx] === "TIME EXPIRED")
    .map(row  => Number(row[totalScoreColIdx]));
  const n = eligibleScores.length;

  const percentileVals    = [];
  const pipelineStatusVals= [];

  data.forEach(row => {
    const testStatus = row[statusColIdx];
    const override   = row[54] || "AUTO"; // col AU
    if (testStatus === "Completed" || testStatus === "TIME EXPIRED") {
      const score      = Number(row[totalScoreColIdx]);
      const countBelow = eligibleScores.filter(s => s < score).length;
      const percentile = n > 0 ? Math.round((countBelow / n) * 1000) / 10 : 0;
      percentileVals.push([percentile]);
      // Auto pipeline status unless HR has overridden
      if (override === "INCLUDE") {
        pipelineStatusVals.push([STATUS_SHORTLISTED_R1]);
      } else if (override === "EXCLUDE") {
        pipelineStatusVals.push([STATUS_NOT_QUALIFIED_TEST]);
      } else {
        pipelineStatusVals.push([percentile >= PERCENTILE_CUTOFF ? STATUS_SHORTLISTED_R1 : STATUS_NOT_QUALIFIED_TEST]);
      }
    } else {
      percentileVals.push([""]);
      pipelineStatusVals.push([""]);
    }
  });

  sheet.getRange(2, 52, percentileVals.length,     1).setValues(percentileVals);      // col AW: percentile (col 52)
  sheet.getRange(2, 53, pipelineStatusVals.length, 1).setValues(pipelineStatusVals);  // col AX: test pipeline status (col 53)
}

// ════════════════════════════════════════════════════════════════════
// QUESTION BANKS
// ════════════════════════════════════════════════════════════════════
const SECTION1_SETS = {
  1: [
    { id:"1-1", q:"Meera has eight physics tests this semester, each scored out of a maximum of 100 points. If her average score on the first six tests was 80, what is the minimum score she could get on the seventh test and still be able to maintain an 80 average across all eight tests?", o:["65","55","60","50"], correctIndex:2 },
    { id:"1-2", q:"If y = x² + mx + 48 has x-intercepts (a, 0) and (b, 0), where a and b are integers, what is the least possible value of m?", o:["-19","-49","-16","-26"], correctIndex:1 },
    { id:"1-3", q:"Let abcd be a general four-digit number and all the digits are non-zero. How many four-digit numbers abcd exist such that the four digits are all distinct and a + b + c + d = 11?", o:["36","12","24","18"], correctIndex:2 },
    { id:"1-4", q:"Vikram starts walking from town X to town Y, a distance of 60 km. One hour after Vikram started, Kiran started walking along the same road from Y to X. If Vikram's walking rate was 5 km/h and Kiran's was 6 km/h, how many kilometres had Kiran walked when they met?", o:["36","24","30","40"], correctIndex:2 },
    { id:"1-5", q:"Suresh is 18 years older than his son. In 4 years, Suresh will be 3 times as old as his son. What will Suresh's age be in 5 years?", o:["27","31","29","25"], correctIndex:2 },
    { id:"1-6", q:"Kavita drives from home to office at a rate of 30 km/h and drives back home along the same route at 45 km/h. What is her average speed for the round trip?", o:["34","38","36","32"], correctIndex:2 },
    { id:"1-7", q:"Arjun sold his bike at a loss of 10 percent of the price that he originally paid for the bike, and then bought another bike at a price of 20 percent less than the price he originally paid for his first bike. If he sold the first bike for ₹5,40,000, what was his net gain, in rupees, for the two transactions?", o:["₹55,000","₹65,000","₹60,000","₹50,000"], correctIndex:2 },
    { id:"1-8", q:"Three machines, A, B, and C, work together to complete a large order. Machine A alone finishes in 8 hours, B alone in 16 hours. All three start together. After 1 hour A breaks down. B and C continue for 4 hours, then B breaks down. C finishes the remaining 1/4 alone. How many hours would C take alone?", o:["18 hours","14 hours","16 hours","20 hours"], correctIndex:2 }
  ],
  2: [
    { id:"2-1", q:"Rahul has eight chemistry tests this semester, each scored out of a maximum of 100 points. If his average score on the first six tests was 88, what is the minimum score he could get on the seventh test and still be able to maintain an 88 average across all eight tests?", o:["80","73","70","76"], correctIndex:3 },
    { id:"2-2", q:"If y = x² + mx + 64 has x-intercepts (a, 0) and (b, 0), where a and b are integers, what is the least possible value of m?", o:["-34","-16","-65","-20"], correctIndex:2 },
    { id:"2-3", q:"Let abcd be a general four-digit number and all the digits are non-zero. How many four-digit numbers abcd exist such that the four digits are all distinct and a + b + c + d = 28?", o:["60","48","24","36"], correctIndex:1 },
    { id:"2-4", q:"Ananya starts walking from town P to town Q, a distance of 80 km. Two hours after Ananya started, Zoya started walking along the same road from Q to P. If Ananya's walking rate was 5 km/h and Zoya's was 9 km/h, how many kilometres had Zoya walked when they met?", o:["40","50","35","45"], correctIndex:3 },
    { id:"2-5", q:"Deepak is 20 years older than his son. In 4 years, Deepak will be 3 times as old as his son. What will Deepak's age be in 5 years?", o:["33","29","35","31"], correctIndex:3 },
    { id:"2-6", q:"Farah drives from home to office at a rate of 36 km/h and drives back home along the same route at 60 km/h. What is her average speed for the round trip?", o:["48","42","45","50"], correctIndex:2 },
    { id:"2-7", q:"Karan sold his scooter at a loss of 15 percent of the price that he originally paid for it, and then bought another scooter at a price of 25 percent less than the price he originally paid for his first scooter. If he sold the first scooter for ₹6,80,000, what was his net gain, in rupees, for the two transactions?", o:["₹75,000","₹85,000","₹70,000","₹80,000"], correctIndex:3 },
    { id:"2-8", q:"Three machines A, B, C work together. A alone finishes in 8 hours, B alone in 24 hours. All start together. After 1 hour A breaks down. B and C continue 4 more hours, then B breaks down. C finishes the remaining 1/3 alone. How many hours would C take alone?", o:["12 hours","20 hours","15 hours","18 hours"], correctIndex:2 }
  ],
  3: [
    { id:"3-1", q:"Priya has eight biology tests this semester, each scored out of a maximum of 100 points. If her average score on the first six tests was 90, what is the minimum score she could get on the seventh test and still be able to maintain a 90 average across all eight tests?", o:["77","84","80","74"], correctIndex:2 },
    { id:"3-2", q:"If y = x² + mx + 50 has x-intercepts (a, 0) and (b, 0), where a and b are integers, what is the least possible value of m?", o:["-15","-51","-30","-27"], correctIndex:1 },
    { id:"3-3", q:"Let abcd be a general four-digit number and all the digits are non-zero. How many four-digit numbers abcd exist such that the four digits are all distinct and a + b + c + d = 13?", o:["48","96","72","60"], correctIndex:2 },
    { id:"3-4", q:"Rohan starts walking from town M to town N, a distance of 90 km. One hour after Rohan started, Ishita started walking along the same road from N to M. If Rohan's walking rate was 6 km/h and Ishita's was 8 km/h, how many kilometres had Ishita walked when they met?", o:["54","45","48","42"], correctIndex:2 },
    { id:"3-5", q:"Manoj is 24 years older than his son. In 3 years, Manoj will be 5 times as old as his son. What will Manoj's age be in 6 years?", o:["31","37","33","35"], correctIndex:2 },
    { id:"3-6", q:"Tanvi drives from home to office at a rate of 50 km/h and drives back home along the same route at 75 km/h. What is her average speed for the round trip?", o:["58","62","60","55"], correctIndex:2 },
    { id:"3-7", q:"Nikhil sold his laptop at a loss of 20 percent of the price he originally paid for it, and then bought another laptop at a price of 30 percent less than the price he originally paid for his first laptop. If he sold the first laptop for ₹3,60,000, what was his net gain, in rupees, for the two transactions?", o:["₹40,000","₹50,000","₹45,000","₹35,000"], correctIndex:2 },
    { id:"3-8", q:"Three machines A, B, C work together. A alone finishes in 8 hours, B alone in 20 hours. All start together. After 2 hours A breaks down. B and C continue 3 more hours, then B breaks down. C finishes the remaining 1/3 alone. How many hours would C take alone?", o:["27 hours","33 hours","30 hours","24 hours"], correctIndex:2 }
  ],
  4: [
    { id:"4-1", q:"Rajesh has eight statistics tests this semester, each scored out of a maximum of 100 points. If his average score on the first six tests was 82, what is the minimum score he could get on the seventh test and still be able to maintain an 82 average across all eight tests?", o:["68","64","58","61"], correctIndex:1 },
    { id:"4-2", q:"If y = x² + mx + 100 has x-intercepts (a, 0) and (b, 0), where a and b are integers, what is the least possible value of m?", o:["-52","-101","-25","-29"], correctIndex:1 },
    { id:"4-3", q:"Let abcd be a general four-digit number and all the digits are non-zero. How many four-digit numbers abcd exist such that the four digits are all distinct and a + b + c + d = 26?", o:["144","96","120","108"], correctIndex:2 },
    { id:"4-4", q:"Aditya starts walking from town A to town B, a distance of 100 km. One hour after Aditya started, Sneha started walking along the same road from B to A. If Aditya's walking rate was 4 km/h and Sneha's was 8 km/h, how many kilometres had Sneha walked when they met?", o:["60","72","56","64"], correctIndex:3 },
    { id:"4-5", q:"Vinod is 28 years older than his son. In 5 years, Vinod will be 3 times as old as his son. What will Vinod's age be in 3 years?", o:["44","40","38","42"], correctIndex:1 },
    { id:"4-6", q:"Radhika drives from home to office at a rate of 20 km/h and drives back home along the same route at 30 km/h. What is her average speed for the round trip?", o:["26","22","28","24"], correctIndex:3 },
    { id:"4-7", q:"Sameer sold his car at a loss of 10 percent of the price he originally paid for it, and then bought another car at a price of 15 percent less than the price he originally paid for his first car. If he sold the first car for ₹9,00,000, what was his net gain, in rupees, for the two transactions?", o:["₹45,000","₹55,000","₹40,000","₹50,000"], correctIndex:3 },
    { id:"4-8", q:"Three machines A, B, C work together. A alone finishes in 8 hours, B alone in 24 hours. All start together. After 2 hours A breaks down. B and C continue 4 more hours, then B breaks down. C finishes remaining 1/3 alone. How many hours would C take alone?", o:["33 hours","40 hours","36 hours","30 hours"], correctIndex:2 }
  ],
  5: [
    { id:"5-1", q:"Farhan has eight statistics tests this semester, each scored out of a maximum of 100 points. If his average score on the first six tests was 84, what is the minimum score he could get on the seventh test and still be able to maintain an 84 average across all eight tests?", o:["72","62","65","68"], correctIndex:3 },
    { id:"5-2", q:"If y = x² + mx + 72 has x-intercepts (a, 0) and (b, 0), where a and b are integers, what is the least possible value of m?", o:["-27","-38","-73","-22"], correctIndex:2 },
    { id:"5-3", q:"Let abcd be a general four-digit number and all the digits are non-zero. How many four-digit numbers abcd exist such that the four digits are all distinct and a + b + c + d = 15?", o:["132","156","144","120"], correctIndex:2 },
    { id:"5-4", q:"Yash starts walking from town R to town S, a distance of 120 km. Two hours after Yash started, Nisha started walking along the same road from S to R. If Yash's walking rate was 5 km/h and Nisha's was 6 km/h, how many kilometres had Nisha walked when they met?", o:["55","65","60","50"], correctIndex:2 },
    { id:"5-5", q:"Anand is 30 years older than his son. In 4 years, Anand will be 4 times as old as his son. What will Anand's age be in 5 years?", o:["39","45","41","43"], correctIndex:2 },
    { id:"5-6", q:"Pooja drives from home to office at a rate of 28 km/h and drives back home along the same route at 70 km/h. What is her average speed for the round trip?", o:["38","42","40","36"], correctIndex:2 },
    { id:"5-7", q:"Imran sold his motorbike at a loss of 25 percent of the price he originally paid for it, and then bought another motorbike at a price of 40 percent less than the price he originally paid for his first motorbike. If he sold the first motorbike for ₹2,40,000, what was his net gain, in rupees, for the two transactions?", o:["₹43,000","₹53,000","₹38,000","₹48,000"], correctIndex:3 },
    { id:"5-8", q:"Three machines A, B, C work together. A alone finishes in 8 hours, B alone in 20 hours. All start together. After 2 hours A breaks down. B and C continue 5 more hours, then B breaks down. C finishes remaining 1/5 alone. How many hours would C take alone?", o:["32 hours","40 hours","35 hours","28 hours"], correctIndex:2 }
  ]
};

const SECTION2_SETS = {
  1: {
    q9:  { text:"Write Python code / pseudo-code to determine the sum of the following series (n as input from the user):\n(i) 5, 12, 21, 32, 45, 60, ... N  [1 mark]\n(ii) 3, 10, 29, 66, 127, 218, ... N  [4 marks]" },
    q10: {
      sales :[["Ravi",1,92],["Ravi",2,85],["Ravi",3,88],["Ravi",4,79],["Meena",1,81],["Meena",2,84],["Meena",3,77],["Meena",4,68],["Suresh",1,75],["Suresh",2,73],["Suresh",3,69],["Farah",1,87],["Farah",2,93]],
      region:[["Ravi","North"],["Meena","South"],["Suresh","East"],["Farah","South"]]
    }
  },
  2: {
    q9:  { text:"Write Python code / pseudo-code to determine the sum of the following series (n as input from the user):\n(i) 4, 10, 18, 28, 40, 54, ... N  [1 mark]\n(ii) 0, 6, 24, 60, 120, 210, ... N  [4 marks]" },
    q10: {
      sales :[["Anil",1,90],["Anil",2,86],["Anil",3,83],["Anil",4,77],["Kavya",1,79],["Kavya",2,82],["Kavya",3,75],["Kavya",4,71],["Rohan",1,72],["Rohan",2,70],["Rohan",3,68],["Divya",1,85],["Divya",2,91]],
      region:[["Anil","North"],["Kavya","South"],["Rohan","East"],["Divya","South"]]
    }
  },
  3: {
    q9:  { text:"Write Python code / pseudo-code to determine the sum of the following series (n as input from the user):\n(i) 2, 3, 6, 11, 18, 27, ... N  [1 mark]\n(ii) 2, 10, 30, 68, 130, 222, ... N  [4 marks]" },
    q10: {
      sales :[["Neha",1,94],["Neha",2,89],["Neha",3,90],["Neha",4,82],["Aisha",1,83],["Aisha",2,86],["Aisha",3,79],["Aisha",4,72],["Manish",1,76],["Manish",2,74],["Manish",3,70],["Prakash",1,88],["Prakash",2,95]],
      region:[["Neha","North"],["Aisha","South"],["Manish","East"],["Prakash","South"]]
    }
  }
};

// ════════════════════════════════════════════════════════════════════
// RETRY WORKFLOW
// ════════════════════════════════════════════════════════════════════
function findUnusedRetryApproval(roll) {
  const sheet = getRetrySheet(), lastRow = sheet.getLastRow();
  if (lastRow < 2) return null;
  const data = sheet.getRange(2,1,lastRow-1,4).getValues();
  for (let i = 0; i < data.length; i++) {
    const isUsed = data[i][3] === true || String(data[i][3]).toUpperCase() === "TRUE";
    if (String(data[i][0]).trim() === roll && !isUsed) return { rowIndex: i+2 };
  }
  return null;
}
function markRetryUsed(rowIndex) {
  const sheet = getRetrySheet();
  sheet.getRange(rowIndex,4).setValue(true);
  sheet.getRange(rowIndex,5).setValue(new Date());
}
function getPreviousSets(roll) {
  const sheet = getSheet(), lastRow = sheet.getLastRow();
  if (lastRow < 2) return null;
  const data = sheet.getRange(2,1,lastRow-1,5).getValues();
  let found = null;
  data.forEach(row => { if (String(row[2]).trim() === roll) found = { set1:row[3], set2:row[4] }; });
  return found;
}
function getRemainingSecondsFromLastDisqualification(roll) {
  const sheet = getSheet(), lastRow = sheet.getLastRow();
  if (lastRow < 2) return TEST_DURATION_SECONDS;
  const data = sheet.getRange(2,1,lastRow-1,7).getValues();
  let lastTaken = null;
  data.forEach(row => {
    if (String(row[2]).trim() === roll && row[5] === "DISQUALIFIED") {
      const parts = String(row[6]).split(":");
      if (parts.length === 2) lastTaken = parseInt(parts[0],10)*60 + parseInt(parts[1],10);
    }
  });
  if (lastTaken === null) return TEST_DURATION_SECONDS;
  const remaining = TEST_DURATION_SECONDS - lastTaken;
  return remaining > 0 ? remaining : 60;
}
function assignSets(excludePrev) {
  let set1 = randomInt(1,5), set2 = randomInt(1,3);
  if (excludePrev) {
    let g = 0; while (set1 === excludePrev.set1 && g++ < 20) set1 = randomInt(1,5);
    g = 0;     while (set2 === excludePrev.set2 && g++ < 20) set2 = randomInt(1,3);
  }
  return { set1, set2 };
}

// ════════════════════════════════════════════════════════════════════
// HEURISTIC SCORING
// ════════════════════════════════════════════════════════════════════
function scoreQ9(answer) {
  if (!answer) return 0;
  const a = answer.toLowerCase(); let s = 0;
  if (/\bfor\b|\bwhile\b/.test(a)) s++;
  if (/\bsum\b|\btotal\b|\+=/.test(a)) s++;
  if (/\binput\s*\(|\bscanf\b|\bcin\s*>>|int\s*\(\s*input/.test(a)) s++;
  if (/\bprint\b|\breturn\b|\bcout\b/.test(a)) s++;
  if (/\bdef\b|\bfunction\b/.test(a)) s++;
  return Math.min(s, Q9_MAX);
}
function scoreQ10(answer) {
  if (!answer) return 0;
  const a = answer.toLowerCase(); let s = 0;
  if (/\bgroup by\b/.test(a)) s++;
  if (/\bmax\s*\(/.test(a)) s++;
  if (/\bmin\s*\(/.test(a)) s++;
  if (/\bavg\s*\(/.test(a)) s++;
  if (/\brank\s*\(|\bdense_rank\s*\(|\brow_number\s*\(|\blimit\b.*\boffset\b/.test(a)) s++;
  if (/\bjoin\b/.test(a)) s++;
  if (/\bleft join\b|\bnot exists\b|\bis null\b/.test(a)) s++;
  if (/\bquarter\b|\bmonth_no\b/.test(a)) s++;
  return Math.min(s, Q10_MAX);
}

// ════════════════════════════════════════════════════════════════════
// REMARKS
// ════════════════════════════════════════════════════════════════════
function buildRemarks(status, unansweredCount, correctCount, timeTakenSeconds) {
  if (status === "DISQUALIFIED") return "Disqualified: proctoring violation (tab switch / window blur).";
  if (status === "TIME EXPIRED") {
    if (unansweredCount === 8) return "Time expired — no Section 1 questions attempted.";
    return `Time expired — ${unansweredCount} of 8 Section 1 questions unanswered.`;
  }
  if (unansweredCount === 8) return "Submitted with no Section 1 questions attempted.";
  if (timeTakenSeconds < 10) return correctCount >= 6
    ? "Unusually fast completion with high score — recommend integrity review."
    : "Unusually fast completion — recommend review (rushed or guessing).";
  if (unansweredCount > 0) return `Incomplete — ${unansweredCount} of 8 Section 1 questions unanswered.`;
  return "No issues observed.";
}

// ════════════════════════════════════════════════════════════════════
// DAILY DIGEST
// ════════════════════════════════════════════════════════════════════
function sendDailyDigest() {
  const sheet = getSheet(), lastRow = sheet.getLastRow();
  if (lastRow < 2) return;
  const data  = sheet.getRange(2,1,lastRow-1,59).getValues();
  const today = new Date(); today.setHours(0,0,0,0);
  const rows  = data.filter(row => new Date(row[0]) >= today);
  if (!rows.length) return;
  let html = `<h2 style="color:#0E489B">InCred Campus Aptitude Test — Daily Summary</h2><p>${rows.length} submission(s) today.</p>`;
  html += `<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:13px;">`;
  html += `<tr style="background:#0E489B;color:white"><th>Name</th><th>Roll</th><th>Status</th><th>Time</th><th>Sec1</th><th>Coding</th><th>Total</th><th>Percentile</th><th>Pipeline Status</th><th>Retry</th><th>Remarks</th></tr>`;
  rows.forEach(r => {
    html += `<tr><td>${r[1]}</td><td>${r[2]}</td><td>${r[5]}</td><td>${r[6]}</td><td>${r[48]}</td><td>${r[49]}</td><td><strong>${r[50]}</strong></td><td>${r[51]}</td><td>${r[52]}</td><td>${r[51]}</td><td>${r[7]}</td></tr>`;
  });
  html += `</table><p style="color:#6e6e6e;font-size:12px;">Coding scores are heuristic — verify before treating as final.</p>`;
  MailApp.sendEmail({ to: DIGEST_RECIPIENT, subject: `InCred Aptitude Test — Daily Summary (${rows.length} submissions)`, htmlBody: html });
}

// ════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════
function sanitizeSection1(questions) { return questions.map(q => ({ id:q.id, q:q.q, o:q.o })); }
function sanitizeSection2(s2) { return { q9:{ text:s2.q9.text }, q10:{ text:buildQ10QuestionText(), table:s2.q10 } }; }
function buildQ10QuestionText() {
  return "Given the Sales, Region, and Month tables shown, write SQL for: " +
    "(i) Best, Worst and Average Revenue by Salesperson [2 marks]; " +
    "(ii) Second Best Revenue by Salesperson [2 marks]; " +
    "(iii) Ranking of Region by average revenue of its salespersons [2 marks]; " +
    "(iv) Count of salespersons by Quarter who recorded no sale [2 marks].";
}
function randomInt(min,max) { return Math.floor(Math.random()*(max-min+1))+min; }
function formatTime(secs) {
  return String(Math.floor(secs/60)).padStart(2,"0")+":"+String(secs%60).padStart(2,"0");
}
function rollNumberExists(roll) {
  if (!roll) return false;
  const sheet = getSheet(), lastRow = sheet.getLastRow();
  if (lastRow < 2) return false;
  return sheet.getRange(2,3,lastRow-1,1).getValues().some(r => String(r[0]).trim() === roll);
}
function logLoginAttempt(name,roll,eventType,result,details) {
  try { getLoginLogSheet().appendRow([new Date(),name,roll,eventType,result,details||""]); } catch(e){}
}
function getSheet()        { return _sheet(SHEET_NAME); }
function getLoginLogSheet(){ return _sheet(LOGIN_LOG_SHEET_NAME); }
function getRetrySheet()   { return _sheet(RETRY_SHEET_NAME); }
function getHRUsersSheet() { return _sheet(HR_USERS_SHEET_NAME); }
function _sheet(name) {
  const s = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
  if (!s) throw new Error(`Sheet tab "${name}" not found.`);
  return s;
}
function jsonOutput(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

/**
 * ════════════════════════════════════════════════════════════════════
 * SETUP INSTRUCTIONS
 * ════════════════════════════════════════════════════════════════════
 *
 * 1. SHEET TABS — create four tabs with these exact names:
 *
 *    "Responses" — 59 columns (A–BG):
 *      A:Timestamp B:Name C:Roll Number (Plain Text) D:Section1 Set E:Section2 Set
 *      F:Status G:Time Taken H:Remarks
 *      I–AF: Q1–Q8 (Text/Answer/Correct/Score ×8 = 32 cols)
 *      AG–AJ: Q9 Text/Answer/Suggested Score/Max
 *      AK–AN: Q10 Text/Answer/Suggested Score/Max
 *      AO:Section1 Score AP:Coding Score AQ:Total Score
 *      AR:Retry Attempt AS:Percentile Rank AT:Pipeline Test Status
 *      AU:Override AV:Round1 Status AW:Round1 Feedback AX:Round2 Status AY:Round2 Feedback
 *
 *    "Login Attempts" — Timestamp|Name|Roll|Event Type|Result|Details
 *    "Retry Approvals" — Roll Number|Approved By|Approved At|Used|Used At
 *    "HR Users" — Email|Name|Role
 *      Role must be exactly "Admin" or "Viewer"
 *      Add ranjana.jaiswal@incred.com with Role=Admin as first row
 *      To add more HR managers later: just add a new row here — no code change needed
 *
 * 2. Apps Script files (Extensions → Apps Script):
 *      Code.gs     → paste this file
 *      Index.html  → paste the student/landing HTML
 *      HRAdmin.html→ paste the HR Admin HTML
 *
 * 3. Deploy → New deployment → Web app
 *    Execute as: Me | Who has access: Anyone → Deploy → Authorize
 *
 * 4. Copy the /exec URL into SCRIPT_URL in both Index.html and HRAdmin.html
 *
 * 5. URLs:
 *    Student / Landing → https://.../exec
 *    HR Admin Portal   → https://.../exec?view=admin
 *    For pretty URLs, ask IT to add redirects:
 *      www.incredfinance.com/CampusAptitudeTest       → student URL
 *      www.incredfinance.com/CampusAptitudeTest/HRAdmin → HR URL
 *
 * 6. Verify: paste YOUR_URL?action=checkRoll&roll=1234567890 in browser
 *    Should return {"exists":false}
 *
 * 7. Daily digest trigger: Triggers → Add → sendDailyDigest → Day timer
 */
