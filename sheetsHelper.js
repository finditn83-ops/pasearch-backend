// =============================================================
// 📊 sheetsHelper.js — Shared Google Sheets logging for PASEARCH
// =============================================================
const { google } = require("googleapis");
const path = require("path");
require("dotenv").config();

/**
 * Append a new row to a specific tab in your Google Sheet.
 * @param {string} sheetName - Name of the tab (e.g., "AdminUpdates")
 * @param {Array} dataRow - Array of values to log
 */
async function logToGoogleSheet(sheetName, dataRow) {
  try {
    const auth = new google.auth.GoogleAuth({
      keyFile: path.join(__dirname, "service-account.json"), // must exist on Render
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });

    await sheets.spreadsheets.values.append({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: `${sheetName}!A1`,
      valueInputOption: "USER_ENTERED",
      resource: { values: [dataRow] },
    });

    console.log(`✅ Logged to Google Sheet tab "${sheetName}"`);
  } catch (err) {
    console.error("❌ Google Sheets logging failed:", err.message);
  }
}

// =============================================================
// 🧾 Specific Helpers for Admin & Police Tabs
// =============================================================
async function logToGoogleSheetInAdminTab(dataRow) {
  await logToGoogleSheet("AdminUpdates", dataRow);
}

async function logToGoogleSheetInPoliceTab(dataRow) {
  await logToGoogleSheet("PoliceUpdates", dataRow);
}

// ✅ Export all
module.exports = {
  logToGoogleSheet,
  logToGoogleSheetInAdminTab,
  logToGoogleSheetInPoliceTab,
};
