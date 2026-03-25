const wheelExtRe = /\.whl(?:\.metadata)?$/;
const sdistExtRe = /\.(tar\.gz|zip|tar\.bz2|tar\.xz)(\.metadata)?$/i;

/**
 * Parses a Python package filename into its name and version components.
 * Supports wheel (.whl), sdist (.tar.gz, .zip, etc.), and their .metadata sidecars.
 *
 * @param {string} filename
 * @returns {{ name: string | undefined, version: string | undefined }}
 */
export function parsePipFilename(filename) {
  const decoded = decodeURIComponent(filename);

  // Wheel: name-version-pytag-abitag-platformtag.whl
  if (wheelExtRe.test(decoded)) {
    const base = decoded.replace(wheelExtRe, "");
    const firstDash = base.indexOf("-");
    if (firstDash > 0) {
      const name = base.slice(0, firstDash);
      const rest = base.slice(firstDash + 1);
      const secondDash = rest.indexOf("-");
      const version = secondDash >= 0 ? rest.slice(0, secondDash) : rest;
      return { name, version };
    }
    return { name: undefined, version: undefined };
  }

  // Source dist: name-version.tar.gz
  if (sdistExtRe.test(decoded)) {
    const base = decoded.replace(sdistExtRe, "");
    const lastDash = base.lastIndexOf("-");
    if (lastDash > 0 && lastDash < base.length - 1) {
      const name = base.slice(0, lastDash);
      const version = base.slice(lastDash + 1);
      return { name, version };
    }
  }

  return { name: undefined, version: undefined };
}
