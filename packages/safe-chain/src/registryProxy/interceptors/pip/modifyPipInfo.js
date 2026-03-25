import { getMinimumPackageAgeHours, getPipMinimumPackageAgeExclusions } from "../../../config/settings.js";
import { ui } from "../../../environment/userInteraction.js";
import { getHeaderValueAsString } from "../../http-utils.js";
import { parsePipFilename } from "./parsePipFilename.js";

const state = {
  hasSuppressedVersions: false,
};

/**
 * Checks if a URL is a PyPI Simple API package index page.
 * These are URLs like:
 *   https://pypi.org/simple/requests/
 *   https://pypi.python.org/simple/requests/
 *
 * @param {string} url
 * @returns {boolean}
 */
export function isSimpleApiUrl(url) {
  try {
    const urlObj = new URL(url);
    const segments = urlObj.pathname.split("/").filter(Boolean);
    return segments.length === 2 && segments[0] === "simple";
  } catch {
    return false;
  }
}

/**
 * Extracts the package name from a Simple API URL.
 * @param {string} url
 * @returns {string | undefined}
 */
function getPackageNameFromSimpleUrl(url) {
  try {
    const urlObj = new URL(url);
    const segments = urlObj.pathname.split("/").filter(Boolean);
    if (segments.length === 2 && segments[0] === "simple") {
      return decodeURIComponent(segments[1]);
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Modifies the request Accept header to force PEP 691 JSON format from PyPI.
 * This ensures we always get structured JSON with upload-time metadata,
 * rather than HTML that would require fragile regex parsing.
 *
 * @param {NodeJS.Dict<string | string[]>} headers
 * @returns {NodeJS.Dict<string | string[]>}
 */
export function modifyPipInfoRequestHeaders(headers) {
  headers["accept"] = "application/vnd.pypi.simple.v1+json";
  return headers;
}

/**
 * Modifies a PyPI Simple API JSON response (PEP 691) to remove files
 * for versions newer than the minimum package age.
 *
 * Each file entry includes an `upload-time` field, so no external API call is needed.
 *
 * @param {Buffer} body
 * @param {NodeJS.Dict<string | string[]> | undefined} headers
 * @param {string} url
 * @returns {Buffer}
 */
export function modifyPipInfoResponse(body, headers, url) {
  try {
    const contentType = getHeaderValueAsString(headers, "content-type");
    if (!contentType?.includes("application/vnd.pypi.simple")) {
      return body;
    }

    if (body.byteLength === 0) {
      return body;
    }

    const packageName = getPackageNameFromSimpleUrl(url);
    if (!packageName) {
      return body;
    }

    // Check if this package is excluded from minimum age filtering
    const exclusions = getPipMinimumPackageAgeExclusions();
    if (exclusions.some((pattern) => matchesExclusionPattern(packageName, pattern))) {
      ui.writeVerbose(
        `Safe-chain: ${packageName} is excluded from minimum package age filtering (pip minimumPackageAgeExclusions setting).`
      );
      return body;
    }

    const json = JSON.parse(body.toString("utf8"));

    if (!json.files || !Array.isArray(json.files)) {
      return body;
    }

    const cutOff = new Date(
      Date.now() - getMinimumPackageAgeHours() * 3600 * 1000
    );

    const originalLength = json.files.length;

    json.files = json.files.filter((/** @type {{ filename: string, "upload-time"?: string }} */ file) => {
      const uploadTime = file["upload-time"];
      if (uploadTime && new Date(uploadTime) > cutOff) {
        state.hasSuppressedVersions = true;
        const version = parsePipFilename(file.filename).version;
        ui.writeVerbose(
          `Safe-chain: ${packageName}==${version || "unknown"} is newer than ${getMinimumPackageAgeHours()} hours and was removed (minimumPackageAgeInHours setting).`
        );
        return false;
      }
      return true;
    });

    if (json.files.length === originalLength) {
      return body;
    }

    // Also filter the versions field if present
    if (json.versions && Array.isArray(json.versions)) {
      // Build set of versions that still have files
      const remainingVersions = new Set();
      for (const file of json.files) {
        const v = parsePipFilename(file.filename).version;
        if (v) remainingVersions.add(v);
      }
      json.versions = json.versions.filter(
        (/** @type {string} */ v) => remainingVersions.has(v)
      );
    }

    if (headers) {
      delete headers["content-length"];
      delete headers["etag"];
      delete headers["last-modified"];
      delete headers["cache-control"];
    }

    return Buffer.from(JSON.stringify(json));
  } catch (/** @type {any} */ err) {
    ui.writeVerbose(
      `Safe-chain: Error modifying PyPI response - bypassing modification. Error: ${err.message}`
    );
    return body;
  }
}

/**
 * @returns {boolean}
 */
export function getHasSuppressedVersions() {
  return state.hasSuppressedVersions;
}

/**
 * Checks if a package name matches an exclusion pattern.
 * @param {string} packageName
 * @param {string} pattern
 * @returns {boolean}
 */
function matchesExclusionPattern(packageName, pattern) {
  const normalizedName = packageName.toLowerCase().replace(/[-_.]+/g, "-");
  const normalizedPattern = pattern.toLowerCase().replace(/[-_.]+/g, "-");

  if (normalizedPattern.endsWith("/*")) {
    return normalizedName.startsWith(normalizedPattern.slice(0, -1));
  }
  return normalizedName === normalizedPattern;
}
