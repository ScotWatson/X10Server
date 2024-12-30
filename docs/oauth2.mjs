/*
(c) 2024 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const selfUrl = new URL(self.location);

let thisRedirectUri;

export function setup(responseType, authorizationUri, tokenUri, clientId) {
  self.sessionStorage.setItem(redirectUri + "_responseType", responseType);
  self.sessionStorage.setItem(redirectUri + "_authorizationUri", authorizationUri);
  self.sessionStorage.setItem(redirectUri + "_tokenUri", tokenUri);
  self.sessionStorage.setItem(redirectUri + "_clientId", clientId);
}
export async function login(redirectUri) {
  thisRedirectUri = redirectUri;
  const thisResponseType = self.sessionStorage.getItem(thisRedirectUri + "_responseType");
  const thisAuthorizationUri = self.sessionStorage.getItem(thisRedirectUri + "_authorizationUri");
  const thisTokenUri = self.sessionStorage.getItem(thisRedirectUri + "_tokenUri");
  const thisClientId = self.sessionStorage.getItem(thisRedirectUri + "_clientId");
  if (!thisResponseType) {
    // do not perform login without a response type
    return;
  }
  switch (thisResponseType) {
    case "token": {
      const params = new URLSearchParams(selfUrl.hash);
      if (params.has("access_token")) {
        self.sessionStorage.setItem(thisRedirectUri + "_accessToken", params.get("access_token"));
        self.sessionStorage.setItem(thisRedirectUri + "_expiresAt", Date.now() + 1000 * params.get("expires_in"));
        self.sessionStorage.removeItem(thisRedirectUri + "_refreshToken");
      } else {
        goToLogin();
        throw new Error("Redirecting to authorization endpoint...");
      }
    }
      break;
    case "code": {
      if (selfUrl.searchParams.has("code")) {
        const code = selfUrl.searchParams.get("code");
        const tokenParameters = new URLSearchParams();
        tokenParameters.append("grant_type", "authorization_code");
        tokenParameters.append("code", code);
        tokenParameters.append("redirect_uri", thisRedirectUri);
        tokenParameters.append("client_id", thisClientId);
        const tokenRequest = new Request(thisTokenUri, {
          method: "POST",
          body: new Blob( [ tokenParameters.toString() ], { type: "application/x-www-form-urlencoded" }),
        });
        return (async () => {
          const tokenResponse = await fetch(tokenRequest);
          if (tokenResponse.status === 200) {
            const tokenResponseParsed = await tokenResponse.json();
            self.sessionStorage.setItem(thisRedirectUri + "_accessToken", tokenResponseParsed.access_token);
            self.sessionStorage.setItem(thisRedirectUri + "_refreshToken", tokenResponseParsed.refresh_token);
            self.sessionStorage.setItem(thisRedirectUri + "_expiresAt", Date.now() + 1000 * tokenResponseParsed.expires_in);
          } else if (tokenResponse.status === 400) {
            goToLogin();
            throw new Error("Bad authorization code. Redirecting to authorization endpoint...");
          } else {
//            goToLogin();
            throw new Error("Unable to continue. Redirecting to authorization endpoint...");
          }
        })();
      } else if (self.sessionStorage.getItem(thisRedirectUri + "_accessToken") !== null) {
        return;
      } else {
        goToLogin();
        throw new Error("Redirecting to authorization endpoint...");
      }
    }
      break;
    default:
      throw new Error("Invalid response type");
  }
}
export function goToLogin() {
  const thisResponseType = self.sessionStorage.getItem(thisRedirectUri + "_responseType");
  const thisAuthorizationUri = self.sessionStorage.getItem(thisRedirectUri + "_authorizationUri");
  const thisTokenUri = self.sessionStorage.getItem(thisRedirectUri + "_tokenUri");
  const thisClientId = self.sessionStorage.getItem(thisRedirectUri + "_clientId");
  if (!thisClientId) {
    throw new Error("Unable to refresh token");
  }
  const authorizationQuery = new URLSearchParams();
  authorizationQuery.append("response_type", "code");
  authorizationQuery.append("client_id", thisClientId);
  authorizationQuery.append("redirect_uri", thisRedirectUri);
  const authorizationLocation = new URL(thisAuthorizationUri.toString() + "?" + authorizationQuery.toString());
  self.location = authorizationLocation.toString();
}
function isTokenExpired() {
  const expiresAt = new Date(Number(self.sessionStorage.getItem(thisRedirectUri + "_expiresAt")));
  if (!expiresAt) {
    return false;
  }
  return (new Date() >= expiresAt);
}
/*
export async function newRequestWithToken(url, options) {
  if (isTokenExpired()) {
    await performRefreshToken();
  }
  const access_token = self.sessionStorage.getItem(thisRedirectUri + "_accessToken");
  if (options.headers) {
    options.headers.append("Authorization", "Bearer " + access_token);
  } else {
    options.headers = new Headers();
    options.headers.append("Authorization", "Bearer " + access_token);
  }
  return new Request(url, options);
}
export async function fetchWithToken(request) {
  let response = await fetch(request);
  if (response.status === 401) {
    await performRefreshToken();
    response = await fetch(request);
  }
  return response;
}
*/
export async function fetchRequestWithToken(url, options) {
  if (isTokenExpired()) {
    try {
      await performRefreshToken();
    } catch (e) {
      goToLogin();
    }
  }
  let access_token = self.sessionStorage.getItem(thisRedirectUri + "_accessToken");
  if (options.headers) {
    options.headers.append("Authorization", "Bearer " + access_token);
  } else {
    options.headers = new Headers();
    options.headers.append("Authorization", "Bearer " + access_token);
  }
  let request = new Request(url, options);
  let response = await fetch(request);
  if (response.status === 401) {
    try {
      await performRefreshToken();
    } catch (e) {
      goToLogin();
    }
    access_token = self.sessionStorage.getItem(thisRedirectUri + "_accessToken");
    options.headers.set("Authorization", "Bearer " + access_token);
    request = new Request(url, options);
    response = await fetch(request);
  }
  return response;
}
export async function performRefreshToken() {
  const thisResponseType = self.sessionStorage.getItem(redirectUri + "_responseType");
  const thisAuthorizationUri = self.sessionStorage.getItem(redirectUri + "_authorizationUri");
  const thisTokenUri = self.sessionStorage.getItem(redirectUri + "_tokenUri");
  const thisClientId = self.sessionStorage.getItem(redirectUri + "_clientId");
  self.sessionStorage.removeItem(thisRedirectUri + "_accessToken");
  const refreshToken = self.sessionStorage.getItem(thisRedirectUri + "_refreshToken");
  if (!(thisTokenUri && refreshToken)) {
    throw new Error("Unable to refresh token");
  }
  const refreshParameters = new URLSearchParams();
  refreshParameters.append("grant_type", "refresh_token");
  refreshParameters.append("refresh_token", refreshToken);
  const refreshRequest = new Request(thisTokenUri, {
    method: "POST",
    body: new Blob( [ refreshParameters.toString() ], { type: "application/x-www-form-urlencoded" }),
  });
  const refreshResponse = await fetch(refreshRequest);
  const refreshResponseParsed = await refreshResponse.json();
  if (refreshResponse.status === 200) {
    console.log("Storing new tokens");
    self.sessionStorage.setItem(thisRedirectUri + "_accessToken", refreshResponseParsed.access_token);
    if (refreshResponseParsed.refresh_token) {
      self.sessionStorage.setItem(thisRedirectUri + "_refreshToken", refreshResponseParsed.refresh_token);
    }
    self.sessionStorage.setItem(thisRedirectUri + "_expiresAt", Date.now() + 1000 * refreshResponseParsed.expires_in);
  } else if (refreshResponse.status === 400) {
    throw new Error("error: " + refreshResponseParsed.error + "\nerror description: " + refreshResponseParsed.error_description + "\nerror URI: " + refreshResponseParsed.error_uri);
  } else {
    throw new Error("Unexpected response to token refresh request");
  }
}
export function getAccessToken() {
  return {
    accessToken: self.sessionStorage.getItem(thisRedirectUri + "_accessToken"),
    expiresAt: self.sessionStorage.getItem(thisRedirectUri + "_expiresAt"),
  };
}
export function setAccessToken(args) {
  self.sessionStorage.setItem(thisRedirectUri + "_accessToken", args.accessToken);
  self.sessionStorage.setItem(thisRedirectUri + "_expiresAt", args.expiresAt);
}
