/*
(c) 2024 Scot Watson  All Rights Reserved
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

const selfUrl = new URL(self.location);

export async function login(response_type, authorizationUri, tokenUri, clientId, redirectUri) {
  switch (response_type) {
    case "token": {
      if (selfUrl.searchParams.has("access_token")) {
        self.sessionStorage.setItem("accessToken", tokenResponseParsed.access_token);
        self.sessionStorage.setItem("expiresAt", Date.now() + 1000 * tokenResponseParsed.expires_in);
        self.sessionStorage.removeItem("refreshToken");
      } else {
        authorizationQuery = new URLSearchParams();
        authorizationQuery.append("response_type", "token");
        authorizationQuery.append("client_id", clientId);
        authorizationQuery.append("redirect_uri", redirectUri);
        authorizationLocation = new URL(authorizationUri.toString() + "?" + authorizationQuery.toString());
        self.location = authorizationLocation.toString();
      }
    }
      break;
    case "code": {
      if (selfUrl.searchParams.has("code")) {
        const code = selfUrl.searchParams.get("code");
        tokenParameters = new URLSearchParams();
        tokenParameters.append("grant_type", "authorization_code");
        tokenParameters.append("code", code);
        tokenParameters.append("redirect_uri", redirectUri);
        tokenParameters.append("client_id", clientId);
        const tokenRequest = new Request(tokenUri, {
          method: "POST",
          body: new Blob( [ tokenParameters.toString() ], { type: "application/x-www-form-urlencoded" }),
        });
        return (async () => {
          const tokenResponse = await fetch(tokenRequest);
          const tokenResponseParsed = await tokenResponse.json();
          self.sessionStorage.setItem("accessToken", tokenResponseParsed.access_token);
          self.sessionStorage.setItem("refreshToken", tokenResponseParsed.refresh_token);
          self.sessionStorage.setItem("expiresAt", Date.now() + 1000 * tokenResponseParsed.expires_in);
        })();
      } else if (self.sessionStorage.hasItem("accessToken")) {
        return;
      } else {
        const authorizationUri = new URL("https://www.scotwatson.x10.mx/login/");
        authorizationQuery = new URLSearchParams();
        authorizationQuery.append("response_type", "code");
        authorizationQuery.append("client_id", clientId);
        authorizationQuery.append("redirect_uri", redirectUri);
        authorizationLocation = new URL(authorizationUri.toString() + "?" + authorizationQuery.toString());
        self.location = authorizationLocation.toString();
      }
    }
      break;
    default:
      throw new Error("Invalid response type");
  }
  function isTokenExpired() {
    const expiresAt = new Date(self.navigator.sessionStorage.get("expiresAt"));
    return (new Date() >= expiresAt);
  }
  async function performRefreshToken() {
    self.sessionStorage.removeItem("accessToken");
    const refreshToken = self.sessionStorage.getItem("refreshToken");
    const tokenUri = new URL("https://www.scotwatson.x10.mx/token/");
    const refreshParameters = new URLSearchParams();
    refreshParameters.append("grant_type", "refresh_token");
    refreshParameters.append("refresh_token", refreshToken);
    const refreshRequest = new Request(tokenUri, {
      method: "POST",
      body: new Blob( [ refreshParameters.toString() ], { type: "application/x-www-form-urlencoded" }),
    });
    const refreshResponse = await fetch(refreshRequest);
    const refreshResponseParsed = refreshResponse.json();
    if (refreshResponse.statusCode == 200) {
      self.sessionStorage.setItem("accessToken", refreshResponse.access_token);
      if (refreshResponse.refresh_token) {
        self.sessionStorage.setItem("refreshToken", refreshResponse.refresh_token);
      }
      self.sessionStorage.setItem("expiresAt", Date.now() + 1000 * refreshResponse.expires_in);
    } else if (refreshResponse.statusCode == 400) {
      throw new Error("error: " + refreshResponseParsed.error + "\nerror description: " + refreshResponseParsed.error_description + "\nerror URI: " + refreshResponseParsed.error_uri);
    } else {
      throw new Error("Unexpected response to token refresh request");
    }
  }
}
export async function fetchWithToken(url, options) {
  if (isTokenExpired()) {
    performRefreshToken();
  }
  const access_token = self.sessionStorage.getItem("accessToken");
  if (options.headers) {
    options.headers.add("Authorization", "Bearer " + access_token);
  }
  return fetch(url, options);
}
