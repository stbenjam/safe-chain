import { getPipCustomRegistries, skipMinimumPackageAge } from "../../config/settings.js";
import { isMalwarePackage } from "../../scanning/audit/index.js";
import { interceptRequests } from "./interceptorBuilder.js";
import {
  isSimpleApiUrl,
  modifyPipInfoRequestHeaders,
  modifyPipInfoResponse,
} from "./pip/modifyPipInfo.js";
import { parsePipFilename } from "./pip/parsePipFilename.js";

const knownPipRegistries = [
  "files.pythonhosted.org",
  "pypi.org",
  "pypi.python.org",
  "pythonhosted.org",
];

/**
 * @param {string} url
 * @returns {import("./interceptorBuilder.js").Interceptor | undefined}
 */
export function pipInterceptorForUrl(url) {
  const customRegistries = getPipCustomRegistries();
  const registries = [...knownPipRegistries, ...customRegistries];
  const registry = registries.find((reg) => url.includes(reg));

  if (registry) {
    return buildPipInterceptor(registry);
  }

  return undefined;
}

/**
 * @param {string} registry
 * @returns {import("./interceptorBuilder.js").Interceptor | undefined}
 */
function buildPipInterceptor(registry) {
  return interceptRequests(async (reqContext) => {
    const { packageName, version } = parsePipPackageFromUrl(
      reqContext.targetUrl,
      registry
    );

    // Normalize underscores to hyphens for DB matching, as PyPI allows underscores in distribution names.
    // Per python, packages that differ only by hyphen vs underscore are considered the same.
    const hyphenName = packageName?.includes("_") ? packageName.replace(/_/g, "-") : packageName;

    const isMalicious =
       await isMalwarePackage(packageName, version)
    || await isMalwarePackage(hyphenName, version);

    if (isMalicious) {
      reqContext.blockMalware(packageName, version);
    }

    // Apply minimum package age filtering for Simple API index pages
    if (!skipMinimumPackageAge() && isSimpleApiUrl(reqContext.targetUrl)) {
      // Force PEP 691 JSON format so we get upload-time metadata inline
      reqContext.modifyRequestHeaders(modifyPipInfoRequestHeaders);
      const targetUrl = reqContext.targetUrl;
      reqContext.modifyBody((body, headers) =>
        modifyPipInfoResponse(body, headers, targetUrl)
      );
    }
  });
}

/**
 * @param {string} url
 * @param {string} registry
 * @returns {{packageName: string | undefined, version: string | undefined}}
 */
function parsePipPackageFromUrl(url, registry) {
  let packageName, version;

  // Basic validation
  if (!registry || typeof url !== "string") {
    return { packageName, version };
  }

  // Quick sanity check on the URL + parse
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    return { packageName, version };
  }

  // Get the last path segment (filename) and decode it (strip query & fragment automatically)
  const lastSegment = urlObj.pathname.split("/").filter(Boolean).pop();
  if (!lastSegment) {
    return { packageName, version };
  }

  const parsed = parsePipFilename(lastSegment);
  packageName = parsed.name;
  version = parsed.version;

  // Reject "latest" as it's a placeholder, not a real version
  // When version is "latest", this signals the URL doesn't contain actual version info
  // Returning undefined allows the request (see registryProxy.js isAllowedUrl)
  if (!packageName || !version || version === "latest") {
    return { packageName: undefined, version: undefined };
  }

  return { packageName, version };
}
