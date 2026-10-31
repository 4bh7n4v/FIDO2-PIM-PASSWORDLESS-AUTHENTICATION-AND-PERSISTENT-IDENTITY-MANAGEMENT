// Windows Hello / FIDO2 helpers: converts between the server's base64url JSON and the browser's ArrayBuffers.

function base64urlToBuffer(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  let binary = "";
  new Uint8Array(buffer).forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function friendlyWebAuthnError(error) {
  if (error && error.name === "NotAllowedError") return "Windows Hello was cancelled or timed out. Try again.";
  if (error && error.name === "InvalidStateError") return "This security key / Windows Hello credential is already registered for this account.";
  if (error && error.name === "NotSupportedError") return "This browser or PC cannot use Windows Hello / FIDO2 here.";
  if (error && error.name === "SecurityError") return "Open the chat page exactly as http://localhost:<port> (not an IP address).";
  return (error && error.message) || String(error);
}

async function createCredential(options) {
  const publicKey = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: { ...options.user, id: base64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: base64urlToBuffer(c.id) })),
  };
  const credential = await navigator.credentials.create({ publicKey });
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  };
}

async function getAssertion(options) {
  const publicKey = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: base64urlToBuffer(c.id) })),
  };
  const credential = await navigator.credentials.get({ publicKey });
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      signature: bufferToBase64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
    },
  };
}
