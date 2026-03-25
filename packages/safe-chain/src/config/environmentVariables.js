/**
 * Gets the minimum package age in hours from environment variable
 * @returns {string | undefined}
 */
export function getMinimumPackageAgeHours() {
  return process.env.SAFE_CHAIN_MINIMUM_PACKAGE_AGE_HOURS;
}

/**
 * Gets the custom npm registries from environment variable
 * Expected format: comma-separated list of registry domains
 * Example: "npm.company.com,registry.internal.net"
 * @returns {string | undefined}
 */
export function getNpmCustomRegistries() {
  return process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES;
}

/**
 * Gets the custom pip registries from environment variable
 * Expected format: comma-separated list of registry domains
 * Example: "pip.company.com,registry.internal.net"
 * @returns {string | undefined}
 */
export function getPipCustomRegistries() {
  return process.env.SAFE_CHAIN_PIP_CUSTOM_REGISTRIES;
}

/**
 * Gets the logging level from environment variable
 * Valid values: "silent", "normal", "verbose"
 * @returns {string | undefined}
 */
export function getLoggingLevel() {
  return process.env.SAFE_CHAIN_LOGGING;
}

/**
 * Gets the minimum package age exclusions from environment variable
 * Expected format: comma-separated list of package names
 * Example: "react,@aikidosec/safe-chain,lodash"
 * @returns {string | undefined}
 */
export function getNpmMinimumPackageAgeExclusions() {
  return process.env.SAFE_CHAIN_NPM_MINIMUM_PACKAGE_AGE_EXCLUSIONS;
}

/**
 * Gets the pip minimum package age exclusions from environment variable
 * Expected format: comma-separated list of package names
 * Example: "requests,django,flask"
 * @returns {string | undefined}
 */
export function getPipMinimumPackageAgeExclusions() {
  return process.env.SAFE_CHAIN_PIP_MINIMUM_PACKAGE_AGE_EXCLUSIONS;
}

/**
 * Gets the pip provenance mode from environment variable
 * Valid values: "default", "strict", "off"
 * @returns {string | undefined}
 */
export function getPipProvenanceMode() {
  return process.env.SAFE_CHAIN_PIP_PROVENANCE_MODE;
}

/**
 * Gets the pip provenance exclusions from environment variable
 * Expected format: comma-separated list of package names
 * Example: "requests,django"
 * @returns {string | undefined}
 */
export function getPipProvenanceExclusions() {
  return process.env.SAFE_CHAIN_PIP_PROVENANCE_EXCLUSIONS;
}
