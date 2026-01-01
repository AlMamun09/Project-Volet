// Session Management and Auth Utilities
const SessionManager = {
  // Config
  inactivityLimit: 15 * 60 * 1000, // 15 minutes
  tokenRefreshThreshold: 2 * 60 * 1000, // Refresh if expiring in 2 mins
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

  getToken() {
    return (
      localStorage.getItem("volet_token") ||
      sessionStorage.getItem("volet_token")
    );
  },

  saveToken(token) {
    if (localStorage.getItem("volet_token")) {
      localStorage.setItem("volet_token", token);
    } else {
      sessionStorage.setItem("volet_token", token);
    }
  },

  checkInactivity() {
    const token = this.getToken();
    if (!token) return;

    const now = Date.now();
    if (now - this.lastActivity > this.inactivityLimit) {
      console.log("User inactive. Auto-logging out...");
      this.logout();
    }
  },

  async checkTokenStatus() {
    const token = this.getToken();
    if (!token) return;

    try {
      // Parse token to get expiration
      const payload = JSON.parse(atob(token.split(".")[1]));
      const exp = payload.exp * 1000; // Convert to ms
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
    } catch (e) {
      console.error("Error checking token:", e);
      this.logout();
    }
  },

  async refreshToken() {
    const token = this.getToken();
    if (!token) return;

    try {
      const res = await fetch("/api/Auth/refresh-token", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.ok) {
        const data = await res.json();
        if (data.token) {
          this.saveToken(data.token);
          console.log("Token refreshed successfully.");
        }
      } else {
        console.warn("Failed to refresh token. Session may expire.");
      }
    } catch (e) {
      console.error("Error refreshing token:", e);
    }
  },

  logout() {
    localStorage.removeItem("volet_token");
    sessionStorage.removeItem("volet_token");
    window.location.href = "/login";
  },

  // UI Updates
  updateUI() {
    const token = this.getToken();
    const authButtons = document.querySelector(".auth-buttons");

    if (authButtons && token) {
      // Check if token is valid (simple check)
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        if (payload.exp * 1000 > Date.now()) {
          // User is logged in
          authButtons.innerHTML = `
                    <button onclick="SessionManager.logout()" class="auth-btn auth-btn-login" style="cursor:pointer; border:none;">
                        Logout
                    </button>
                `;
        }
      } catch (e) {
        this.logout();
      }
    }
  },
};

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  SessionManager.init();
});
