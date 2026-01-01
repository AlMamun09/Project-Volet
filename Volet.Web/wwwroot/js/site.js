// Session Management and Auth Utilities
const SessionManager = {
  // Config
  inactivityLimit: 15 * 60 * 1000, // 15 minutes
  tokenRefreshThreshold: 1 * 60 * 1000, // Refresh if expiring in 1 min (token lives ~10 min, refreshes at ~9 min mark)
  checkInterval: 60 * 1000, // Check every minute

  // State
  lastActivity: Date.now(),
  checkTimer: null,

  init() {
    this.setupActivityListeners();
    this.startMonitoring();
    this.updateUI();
  },

  setupActivityListeners() {
    const resetActivity = () => {
      this.lastActivity = Date.now();
    };

    window.addEventListener("mousemove", resetActivity);
    window.addEventListener("click", resetActivity);
    window.addEventListener("keydown", resetActivity);
    window.addEventListener("scroll", resetActivity);
  },

  startMonitoring() {
    // Run checks periodically
    this.checkTimer = setInterval(() => {
      this.checkInactivity();
      this.checkTokenStatus();
    }, this.checkInterval);

    // Run initial check immediately
    this.checkTokenStatus();
  },

  getTokenStatus() {
    // We don't have the token anymore (it's HttpOnly).
    // We check the "volet_session" cookie for the expiration timestamp.
    const name = "volet_session=";
    const decodedCookie = decodeURIComponent(document.cookie);
    const ca = decodedCookie.split(";");
    for (let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) == " ") {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        const exp = c.substring(name.length, c.length);
        return parseInt(exp); // timestamp in seconds
      }
    }
    return null;
  },

  checkInactivity() {
    // Only check if we are logged in
    if (!this.getTokenStatus()) return;

    const now = Date.now();
    if (now - this.lastActivity > this.inactivityLimit) {
      console.log("User inactive. Auto-logging out...");
      this.logout();
    }
  },

  async checkTokenStatus() {
    const expSeconds = this.getTokenStatus();
    if (!expSeconds) return; // Not logged in

    const exp = expSeconds * 1000;
    const now = Date.now();
    const timeRemaining = exp - now;

    // If token is expired, logout
    if (timeRemaining <= 0) {
      console.log("Token expired. Logging out...");
      this.logout();
      return;
    }

    // If token is about to expire (within 2 mins) AND user is active
    if (timeRemaining < this.tokenRefreshThreshold) {
      console.log("Token expiring soon. Refreshing...");
      await this.refreshToken();
    }
  },

  async refreshToken() {
    try {
      // No headers needed - Cookies are sent automatically
      const res = await fetch("/api/Auth/refresh-token", {
        method: "POST",
      });

      if (res.ok) {
        console.log("Token refreshed successfully.");
      } else {
        console.warn("Failed to refresh token. Session may expire.");
      }
    } catch (e) {
      console.error("Error refreshing token:", e);
    }
  },

  async logout() {
    try {
      await fetch("/api/Auth/logout", { method: "POST" });
    } catch (e) {
      console.error("Logout failed", e);
    }
    window.location.href = "/login";
  },

  // UI Updates
  updateUI() {
    const expSeconds = this.getTokenStatus();
    const authButtons = document.querySelector(".auth-buttons");

    if (authButtons && expSeconds) {
      if (expSeconds * 1000 > Date.now()) {
        // User is logged in
        authButtons.innerHTML = `
                <button onclick="SessionManager.logout()" class="auth-btn auth-btn-login" style="cursor:pointer; border:none;">
                    Logout
                </button>
            `;
      }
    }
  },
};

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  SessionManager.init();
});
