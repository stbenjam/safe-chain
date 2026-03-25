import { describe, it, mock } from "node:test";
import assert from "node:assert";

describe("pipInterceptor minimum package age", async () => {
  let minimumPackageAgeSettings = 48;
  let skipMinimumPackageAgeSetting = false;
  let minimumPackageAgeExclusionsSetting = [];

  mock.module("../../../config/settings.js", {
    namedExports: {
      getMinimumPackageAgeHours: () => minimumPackageAgeSettings,
      skipMinimumPackageAge: () => skipMinimumPackageAgeSetting,
      getPipCustomRegistries: () => [],
      getPipMinimumPackageAgeExclusions: () => minimumPackageAgeExclusionsSetting,
    },
  });

  mock.module("../../../scanning/audit/index.js", {
    namedExports: {
      isMalwarePackage: async () => false,
    },
  });

  mock.module("../../../environment/userInteraction.js", {
    namedExports: {
      ui: {
        startProcess: () => {},
        writeError: () => {},
        writeInformation: () => {},
        writeWarning: () => {},
        writeVerbose: () => {},
        writeExitWithoutInstallingMaliciousPackages: () => {},
        emptyLine: () => {},
      },
    },
  });

  const { pipInterceptorForUrl } = await import("../pipInterceptor.js");

  // --- Simple API URL detection ---

  for (const simpleApiUrl of [
    "https://pypi.org/simple/requests/",
    "https://pypi.org/simple/django/",
    "https://pypi.org/simple/Flask/",
    "https://pypi.python.org/simple/requests/",
  ]) {
    it(`modifyResponse should be true for Simple API URLs: ${simpleApiUrl}`, async () => {
      const interceptor = pipInterceptorForUrl(simpleApiUrl);
      const requestInterceptor = await interceptor.handleRequest(simpleApiUrl);
      assert.equal(requestInterceptor.modifiesResponse(), true);
    });
  }

  for (const nonSimpleUrl of [
    "https://files.pythonhosted.org/packages/xx/yy/requests-2.31.0.tar.gz",
    "https://files.pythonhosted.org/packages/xx/yy/requests-2.31.0-py3-none-any.whl",
    "https://pypi.org/project/requests/",
    "https://pypi.org/simple/",
  ]) {
    it(`modifyResponse should be false for non-Simple-API URLs: ${nonSimpleUrl}`, async () => {
      const interceptor = pipInterceptorForUrl(nonSimpleUrl);
      if (!interceptor) return;
      const requestInterceptor = await interceptor.handleRequest(nonSimpleUrl);
      assert.equal(requestInterceptor.modifiesResponse(), false);
    });
  }

  // --- Request header modification ---

  it("Should set Accept header to request PEP 691 JSON", async () => {
    minimumPackageAgeSettings = 24;
    skipMinimumPackageAgeSetting = false;

    const url = "https://pypi.org/simple/requests/";
    const interceptor = pipInterceptorForUrl(url);
    const requestInterceptor = await interceptor.handleRequest(url);

    const headers = { "accept": "text/html" };
    requestInterceptor.modifyRequestHeaders(headers);
    assert.equal(headers["accept"], "application/vnd.pypi.simple.v1+json");
  });

  // --- JSON response filtering ---

  it("Should remove versions newer than the threshold", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = [];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-7) },
      { version: "2.0.0", uploadTime: getDate(-4) },
      { version: "3.0.0", uploadTime: getDate(-3) },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    assert.equal(parsed.files.length, 2); // 1.0.0 has whl + tar.gz
    assert.deepEqual(parsed.versions, ["1.0.0"]);
  });

  it("Should remove versions newer than the threshold (wheels)", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = [];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-7) },
      { version: "2.0.0", uploadTime: getDate(-3) },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    // Only 1.0.0 files should remain
    assert.ok(parsed.files.every((f) => f.filename.includes("1.0.0")));
    assert.ok(!parsed.files.some((f) => f.filename.includes("2.0.0")));
  });

  // --- Skip minimum package age ---

  it("Should not filter packages when skipMinimumPackageAge is enabled", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = true;
    minimumPackageAgeExclusionsSetting = [];

    const url = "https://pypi.org/simple/requests/";
    const interceptor = pipInterceptorForUrl(url);
    const requestInterceptor = await interceptor.handleRequest(url);

    assert.equal(requestInterceptor.modifiesResponse(), false);
  });

  // --- Exclusions ---

  it("Should not filter packages when package is in exclusion list", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = ["requests"];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-7) },
      { version: "2.0.0", uploadTime: getDate(-3) },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    // All files should remain since requests is excluded
    assert.ok(parsed.files.some((f) => f.filename.includes("1.0.0")));
    assert.ok(parsed.files.some((f) => f.filename.includes("2.0.0")));
  });

  it("Should filter packages when package is NOT in exclusion list", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = ["django"];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-7) },
      { version: "2.0.0", uploadTime: getDate(-3) },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    assert.ok(parsed.files.some((f) => f.filename.includes("1.0.0")));
    assert.ok(!parsed.files.some((f) => f.filename.includes("2.0.0")));
  });

  it("Should handle PEP 503 normalized names in exclusion matching", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = ["foo_bar"]; // underscore in exclusion

    const json = buildSimpleJson("foo-bar", [
      { version: "1.0.0", uploadTime: getDate(-7), namePrefix: "foo_bar" },
      { version: "2.0.0", uploadTime: getDate(-3), namePrefix: "foo_bar" },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/foo-bar/",
      json
    );

    const parsed = JSON.parse(result);
    // All versions should remain since foo_bar normalizes to foo-bar
    assert.ok(parsed.files.some((f) => f.filename.includes("1.0.0")));
    assert.ok(parsed.files.some((f) => f.filename.includes("2.0.0")));
  });

  // --- Custom minimum package age ---

  it("Should use custom minimum package age of 48 hours", async () => {
    minimumPackageAgeSettings = 48;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = [];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-72) },
      { version: "2.0.0", uploadTime: getDate(-50) },
      { version: "3.0.0", uploadTime: getDate(-40) },
      { version: "4.0.0", uploadTime: getDate(-24) },
    ]);

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    assert.ok(parsed.files.some((f) => f.filename.includes("1.0.0")));
    assert.ok(parsed.files.some((f) => f.filename.includes("2.0.0")));
    assert.ok(!parsed.files.some((f) => f.filename.includes("3.0.0")));
    assert.ok(!parsed.files.some((f) => f.filename.includes("4.0.0")));
  });

  // --- No upload-time field ---

  it("Should keep files that have no upload-time field", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = [];

    const json = JSON.stringify({
      name: "requests",
      versions: ["1.0.0"],
      files: [
        {
          filename: "requests-1.0.0.tar.gz",
          url: "/packages/requests-1.0.0.tar.gz",
          // no upload-time field
        },
      ],
      meta: { "api-version": "1.4" },
    });

    const result = await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json
    );

    const parsed = JSON.parse(result);
    assert.equal(parsed.files.length, 1);
  });

  // --- Cache headers removed ---

  it("Should remove cache and content-length headers when response is modified", async () => {
    minimumPackageAgeSettings = 5;
    skipMinimumPackageAgeSetting = false;
    minimumPackageAgeExclusionsSetting = [];

    const json = buildSimpleJson("requests", [
      { version: "1.0.0", uploadTime: getDate(-7) },
      { version: "2.0.0", uploadTime: getDate(-3) },
    ]);

    const headers = {
      "content-type": "application/vnd.pypi.simple.v1+json",
      "etag": "\"abc123\"",
      "last-modified": "Thu, 01 Jan 2025 00:00:00 GMT",
      "cache-control": "max-age=600",
      "content-length": "99999",
    };

    await runModifyPipInfoRequest(
      "https://pypi.org/simple/requests/",
      json,
      headers
    );

    assert.equal(headers["etag"], undefined);
    assert.equal(headers["last-modified"], undefined);
    assert.equal(headers["cache-control"], undefined);
    assert.equal(headers["content-length"], undefined);
  });

  // --- Helper functions ---

  function getDate(plusHours) {
    const date = new Date();
    date.setHours(date.getHours() + plusHours);
    return date.toISOString();
  }

  function buildSimpleJson(packageName, versions) {
    const files = [];
    const versionList = [];

    for (const v of versions) {
      const prefix = v.namePrefix || packageName;
      versionList.push(v.version);
      files.push({
        filename: `${prefix}-${v.version}-py3-none-any.whl`,
        url: `/packages/${prefix}-${v.version}-py3-none-any.whl`,
        "upload-time": v.uploadTime,
      });
      files.push({
        filename: `${prefix}-${v.version}.tar.gz`,
        url: `/packages/${prefix}-${v.version}.tar.gz`,
        "upload-time": v.uploadTime,
      });
    }

    return JSON.stringify({
      name: packageName,
      versions: versionList,
      files,
      meta: { "api-version": "1.4" },
    });
  }

  async function runModifyPipInfoRequest(url, body, headers) {
    if (!headers) {
      headers = { "content-type": "application/vnd.pypi.simple.v1+json" };
    }

    const interceptor = pipInterceptorForUrl(url);
    const requestHandler = await interceptor.handleRequest(url);

    if (requestHandler.modifiesResponse()) {
      const modifiedBuffer = requestHandler.modifyBody(
        Buffer.from(body),
        headers
      );
      return modifiedBuffer.toString("utf8");
    }

    return body;
  }
});
