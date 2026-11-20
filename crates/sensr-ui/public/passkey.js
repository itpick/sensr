// WebAuthn passkey ceremonies for sensr.
//
// The server issues the challenge and keeps its state; this file only talks to
// the authenticator and posts the signed answer back. It is a plain script so
// the login page works without the wasm bundle.
(function () {
  "use strict";

  function b64urlToBuffer(value) {
    var text = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (text.length % 4) text += "=";
    var raw = atob(text);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    }).then(function (response) {
      return response.text().then(function (text) {
        var data = null;
        try {
          data = text ? JSON.parse(text) : null;
        } catch (e) {
          data = null;
        }
        if (!response.ok) {
          var message =
            (data && (data.message || data.error)) ||
            text ||
            "The server rejected the request (" + response.status + ").";
          throw new Error(message);
        }
        return data;
      });
    });
  }

  function creationOptions(options) {
    options.challenge = b64urlToBuffer(options.challenge);
    options.user.id = b64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(function (c) {
        c.id = b64urlToBuffer(c.id);
        return c;
      });
    }
    return options;
  }

  function requestOptions(options) {
    options.challenge = b64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(function (c) {
        c.id = b64urlToBuffer(c.id);
        return c;
      });
    }
    return options;
  }

  function registrationResponse(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToB64url(response.attestationObject),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        transports:
          typeof response.getTransports === "function"
            ? response.getTransports()
            : undefined,
      },
      clientExtensionResults:
        typeof credential.getClientExtensionResults === "function"
          ? credential.getClientExtensionResults()
          : {},
    };
  }

  function assertionResponse(credential) {
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bufferToB64url(response.authenticatorData),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        signature: bufferToB64url(response.signature),
      },
      clientExtensionResults:
        typeof credential.getClientExtensionResults === "function"
          ? credential.getClientExtensionResults()
          : {},
    };
    if (response.userHandle) {
      out.response.userHandle = bufferToB64url(response.userHandle);
    }
    return out;
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  function explain(error) {
    if (error && error.name === "NotAllowedError") {
      return "The passkey prompt was dismissed or timed out.";
    }
    if (error && error.name === "InvalidStateError") {
      return "That passkey is already registered on this account.";
    }
    if (error && error.message) return error.message;
    return "The passkey ceremony failed.";
  }

  function login() {
    var button = document.getElementById("passkey-login");
    var error = document.getElementById("passkey-error");
    if (!button || !supported()) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      button.disabled = true;
      if (error) error.hidden = true;
      post("/ui/fn/passkey/login/start", {})
        .then(function (started) {
          if (!started || !started.options) {
            throw new Error("No passkey is registered yet. Sign in with a password and add one.");
          }
          return navigator.credentials
            .get({ publicKey: requestOptions(started.options) })
            .then(function (credential) {
              return post("/ui/fn/passkey/login/finish", {
                state: started.state,
                credential: assertionResponse(credential),
              });
            });
        })
        .then(function () {
          window.location.assign("/");
        })
        .catch(function (e) {
          if (error) {
            error.textContent = explain(e);
            error.hidden = false;
          }
          button.disabled = false;
        });
    });
  }

  function register() {
    var button = document.getElementById("passkey-add");
    var error = document.getElementById("passkey-card-error");
    var notice = document.getElementById("passkey-card-notice");
    if (!button || !supported()) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      var name = document.getElementById("passkey_name");
      button.disabled = true;
      if (error) error.hidden = true;
      if (notice) notice.hidden = true;
      post("/ui/fn/passkey/register/start", {})
        .then(function (started) {
          return navigator.credentials
            .create({ publicKey: creationOptions(started.options) })
            .then(function (credential) {
              return post("/ui/fn/passkey/register/finish", {
                state: started.state,
                name: name && name.value ? name.value : "Passkey",
                credential: registrationResponse(credential),
              });
            });
        })
        .then(function () {
          window.location.assign("/ui/core/password?passkey=added");
        })
        .catch(function (e) {
          if (error) {
            error.textContent = explain(e);
            error.hidden = false;
          }
          button.disabled = false;
        });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      login();
      register();
    });
  } else {
    login();
    register();
  }
})();