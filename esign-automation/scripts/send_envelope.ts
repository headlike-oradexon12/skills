import { createHash } from "crypto";
import { promises as fs } from "fs";
import * as path from "path";

interface Credentials {
  clientId: string;
  clientSecret: string;
  dataCenter: "AS1" | "AS2" | "EU1" | "SML";
}

interface Signer {
  userName: string;
  userEmail: string;
  signOrder?: number;
}

interface ScriptOutput {
  success: boolean;
  step?: string;
  message: string;
  data?: unknown;
  error?: string;
}

interface RequestOptions {
  step: string;
  action: string;
  url: string;
  init: RequestInit;
  timeoutMs?: number;
}

interface JsonRequestOptions<T> extends RequestOptions {
  errorPrefix: string;
  validate: (data: unknown) => T;
}

const DEFAULT_SUBJECT = "Please sign this document";
const REQUEST_TIMEOUT_MS = 30_000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".doc": "application/msword",
  ".docx":
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".txt": "text/plain",
};
const BASE_URLS: Record<Credentials["dataCenter"], string> = {
  SML: "https://openapi-sml.esignglobal.com",
  AS1: "https://openapi-as1.esignglobal.com",
  AS2: "https://openapi-as2.esignglobal.com",
  EU1: "https://openapi-eu1.esignglobal.com",
};

function computeContentMd5(fileBuffer: Buffer): string {
  return createHash("md5").update(fileBuffer).digest("base64");
}

function detectContentType(fileName: string): string {
  const ext = path.extname(fileName).toLowerCase();
  return CONTENT_TYPES[ext] ?? "application/octet-stream";
}

function parseSigners(raw: unknown): Signer[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error("signersJson must be a non-empty array.");
  }

  const normalized = raw.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Signer at index ${index} must be an object`);
    }

    const signer = entry as Partial<Signer>;
    const userName =
      typeof signer.userName === "string" ? signer.userName.trim() : "";
    const userEmail =
      typeof signer.userEmail === "string" ? signer.userEmail.trim() : "";

    if (!userName) {
      throw new Error(`Signer at index ${index} missing userName`);
    }

    if (!userEmail || !EMAIL_REGEX.test(userEmail)) {
      throw new Error(
        `Signer at index ${index} invalid email '${String(signer.userEmail ?? "")}'`,
      );
    }

    if (
      signer.signOrder !== undefined &&
      (!Number.isInteger(signer.signOrder) || signer.signOrder < 1)
    ) {
      throw new Error(
        `Signer at index ${index} invalid signOrder, must be >= 1`,
      );
    }

    return {
      userName,
      userEmail,
      signOrder: signer.signOrder,
    };
  });

  const duplicateEmails = normalized
    .map((signer) => signer.userEmail.toLowerCase())
    .filter((email, index, emails) => emails.indexOf(email) !== index);

  if (duplicateEmails.length > 0) {
    throw new Error(`Duplicate signer email detected: ${duplicateEmails[0]}`);
  }

  return normalized;
}

function exitWithOutput(output: ScriptOutput, code = 0): never {
  const payload = JSON.stringify(output, null, 2);

  if (code === 0) {
    console.log(payload);
  } else {
    console.error(payload);
  }

  process.exit(code);
}

function parseJson<T>(text: string, context: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${context} returned invalid JSON`);
  }
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function parseAppKey(): Credentials {
  const appKey = process.env.ESIGNGLOBAL_APIKEY?.trim();

  if (!appKey) {
    throw new Error("Missing ESIGNGLOBAL_APIKEY");
  }

  const [dataCenter, clientId, ...secretParts] = appKey.split("_");

  if (!dataCenter || !clientId || secretParts.length === 0) {
    throw new Error("Invalid ESIGNGLOBAL_APIKEY");
  }

  if (!(dataCenter in BASE_URLS)) {
    throw new Error("Invalid ESIGNGLOBAL_APIKEY");
  }

  return {
    dataCenter: dataCenter as Credentials["dataCenter"],
    clientId,
    clientSecret: secretParts.join("_"),
  };
}

function getBaseUrl(dataCenter: Credentials["dataCenter"]): string {
  return BASE_URLS[dataCenter];
}

async function fetchWithTimeout({
  step,
  action,
  url,
  init,
  timeoutMs = REQUEST_TIMEOUT_MS,
}: RequestOptions): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    });

    return response;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`${action} timed out after ${timeoutMs}ms`);
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function requestText(
  options: RequestOptions,
): Promise<{ response: Response; text: string }> {
  const response = await fetchWithTimeout(options);
  const text = await response.text();

  return { response, text };
}

async function requestJson<T>(options: JsonRequestOptions<T>): Promise<T> {
  const { response, text } = await requestText(options);

  if (!response.ok) {
    throw new Error(`${options.errorPrefix} HTTP ${response.status}: ${text}`);
  }

  const data = parseJson<unknown>(text, options.action);
  return options.validate(data);
}

function validateTokenResponse(data: unknown): { access_token: string } {
  if (
    !data ||
    typeof data !== "object" ||
    typeof (data as { access_token?: unknown }).access_token !== "string"
  ) {
    throw new Error("Invalid token response: missing access_token");
  }

  return data as { access_token: string };
}

function validateUploadUrlResponse(data: unknown): {
  fileKey: string;
  fileUploadUrl: string;
} {
  if (!data || typeof data !== "object") {
    throw new Error("Upload URL API returned an invalid payload");
  }

  const payload = data as {
    code?: number | string;
    message?: string;
    data?: { fileKey?: unknown; fileUploadUrl?: unknown };
  };

  if (payload.code !== 0 && payload.code !== "0") {
    throw new Error(
      payload.message || `Upload URL API error: ${JSON.stringify(payload)}`,
    );
  }

  if (
    typeof payload.data?.fileKey !== "string" ||
    typeof payload.data?.fileUploadUrl !== "string"
  ) {
    throw new Error("Upload URL response missing fileKey or fileUploadUrl");
  }

  return {
    fileKey: payload.data.fileKey,
    fileUploadUrl: payload.data.fileUploadUrl,
  };
}

function validateEnvelopeResponse(data: unknown): unknown {
  if (!data || typeof data !== "object") {
    throw new Error("Envelope API returned an invalid payload");
  }

  const payload = data as { code?: number | string; message?: string };

  if (payload.code !== 0 && payload.code !== "0") {
    throw new Error(
      payload.message ||
        `API error initiating envelope: ${JSON.stringify(payload)}`,
    );
  }

  return data;
}

async function getAccessToken(creds: Credentials): Promise<string> {
  const params = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    grant_type: "client_credentials",
  });

  const data = await requestJson({
    step: "Step1",
    action: "GET_TOKEN",
    url: `${getBaseUrl(creds.dataCenter)}/esignglobal/v1/oauth2/accessToken`,
    init: {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    },
    errorPrefix: "Token API",
    validate: validateTokenResponse,
  });

  return data.access_token;
}

async function getUploadUrl(
  accessToken: string,
  creds: Credentials,
  fileName: string,
  contentType: string,
  contentMd5: string,
): Promise<{ fileKey: string; fileUploadUrl: string }> {
  const body = { fileName, contentType, contentMD5: contentMd5 };

  return requestJson({
    step: "Step2",
    action: "GET_UPLOAD_URL",
    url: `${getBaseUrl(creds.dataCenter)}/esignglobal/v1/files/getUploadUrl`,
    init: {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    },
    errorPrefix: "Upload URL API",
    validate: validateUploadUrlResponse,
  });
}

async function uploadDocument(
  uploadUrl: string,
  fileBuffer: Buffer,
  contentType: string,
  contentMd5: string,
): Promise<void> {
  const { response, text } = await requestText({
    step: "Step3",
    action: "UPLOAD_DOCUMENT",
    url: uploadUrl,
    init: {
      method: "PUT",
      headers: {
        "Content-Type": contentType,
        "Content-MD5": contentMd5,
      },
      body: fileBuffer,
    },
    timeoutMs: 120_000,
  });

  if (!response.ok) {
    throw new Error(`Upload PUT failed HTTP ${response.status}: ${text}`);
  }
}

async function startEnvelope(
  accessToken: string,
  creds: Credentials,
  fileKey: string,
  fileName: string,
  signers: Signer[],
  subject?: string,
): Promise<unknown> {
  const signerInfos = signers.map((signer) => ({
    userName: signer.userName,
    userEmail: signer.userEmail,
    signOrder: String(signer.signOrder ?? 1),
    freeFormSign: true,
  }));

  const body = {
    subject: subject?.trim() || path.parse(fileName).name || DEFAULT_SUBJECT,
    signFiles: [{ fileKey }],
    signerInfos,
  };

  return requestJson({
    step: "Step4",
    action: "START_ENVELOPE",
    url: `${getBaseUrl(creds.dataCenter)}/esignglobal/v1/envelope/createAndStart`,
    init: {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    },
    errorPrefix: "Envelope API",
    validate: validateEnvelopeResponse,
  });
}

async function validateFile(
  filePath: string,
): Promise<{ fileName: string; fileBuffer: Buffer }> {
  let stats;

  try {
    stats = await fs.stat(filePath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;

    if (code === "ENOENT") {
      throw new Error(`File not found: ${filePath}`);
    }

    throw error;
  }

  if (!stats.isFile()) {
    throw new Error(`Path is not a file: ${filePath}`);
  }

  if (stats.size === 0) {
    throw new Error(`File is empty: ${filePath}`);
  }

  return {
    fileName: path.basename(filePath),
    fileBuffer: await fs.readFile(filePath),
  };
}

function getUsage(): string {
  return "Usage: tsx send_envelope.ts send <filePath> <signersJson> [subject]";
}

async function handleSend(args: string[]): Promise<never> {
  if (args.length < 2) {
    exitWithOutput(
      {
        success: false,
        step: "send",
        message: "Missing args",
        error: getUsage(),
      },
      1,
    );
  }

  const filePath = path.resolve(args[0]);
  const signersJson = args[1];
  const subject = args.slice(2).join(" ").trim() || undefined;

  let signers: Signer[];
  try {
    signers = parseSigners(parseJson<unknown>(signersJson, "signersJson"));
  } catch (error) {
    exitWithOutput(
      {
        success: false,
        step: "send",
        message: "Invalid signersJson",
        error: getErrorMessage(error),
      },
      1,
    );
  }

  try {
    const { fileName, fileBuffer } = await validateFile(filePath);
    const creds = parseAppKey();
    const contentType = detectContentType(fileName);
    const contentMd5 = computeContentMd5(fileBuffer);
    const accessToken = await getAccessToken(creds);
    const { fileKey, fileUploadUrl } = await getUploadUrl(
      accessToken,
      creds,
      fileName,
      contentType,
      contentMd5,
    );

    await uploadDocument(fileUploadUrl, fileBuffer, contentType, contentMd5);
    const envelopeResponse = await startEnvelope(
      accessToken,
      creds,
      fileKey,
      fileName,
      signers,
      subject,
    );

    exitWithOutput({
      success: true,
      step: "send",
      message: "Envelope initiated successfully",
      data: {
        filePath,
        fileKey,
        envelopeResponse,
      },
    });
  } catch (error) {
    exitWithOutput(
      {
        success: false,
        step: "send",
        message: "Failed to execute envelope flow",
        error: getErrorMessage(error),
      },
      1,
    );
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] !== "send") {
    exitWithOutput(
      {
        success: false,
        message: "Missing or invalid command",
        error: getUsage(),
      },
      1,
    );
  }

  await handleSend(args.slice(1));
}

main().catch((error) => {
  exitWithOutput(
    {
      success: false,
      message: "Unexpected script failure",
      error: getErrorMessage(error),
    },
    1,
  );
});
