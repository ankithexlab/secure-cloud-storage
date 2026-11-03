# =============================================================================
# app.py — Secure Cloud API entry-point
# =============================================================================
import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from routes.auth import auth_bp
from routes.file import file_bp
from routes.keys import keys_bp
from routes.tokens import tokens_bp
from routes.shares import shares_bp
from routes.admin import admin_bp

API_PREFIX = "/api"


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    # CORS configuration
    CORS(
        app,
        resources={r"/*": {"origins": Config.CORS_ORIGINS}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Access-Token", "X-Share-Token"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        expose_headers=[
            "Content-Disposition",
            "X-IV",
            "X-Salt",
            "X-Wrapped-Key",
            "X-Key-Fingerprint",
            "X-Original-Mime",
            "X-Is-Legacy",
            "X-Deprecated",
            "X-Integrity-Hash",
            "X-Algorithm",
            "X-Token-Downloads-Remaining",
            "X-Share-Downloads-Remaining",
            "X-Share-Permission",
            "Content-Length",
        ],
    )

    @app.before_request
    def log_request():
        # Prevent token leakage in logs
        path = request.path
        if "/access/download/" in path:
            path = f"{API_PREFIX}/access/download/[MASKED_TOKEN]"
        elif "/shares/access/" in path:
            path = f"{API_PREFIX}/shares/access/[MASKED_TOKEN]"
        print(f"Incoming Request: {request.method} {path} from {request.remote_addr}")

    @app.after_request
    def set_security_headers(response):
        """Inject strict OWASP defensive security headers on every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
        if Config.IS_PRODUCTION or request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    app.register_blueprint(auth_bp, url_prefix=API_PREFIX)
    app.register_blueprint(file_bp, url_prefix=API_PREFIX)
    app.register_blueprint(keys_bp, url_prefix=API_PREFIX)
    app.register_blueprint(tokens_bp, url_prefix=API_PREFIX)
    app.register_blueprint(shares_bp, url_prefix=API_PREFIX)
    app.register_blueprint(admin_bp, url_prefix=f"{API_PREFIX}/admin")

    @app.route("/health", methods=["GET"])
    @app.route(f"{API_PREFIX}/health", methods=["GET"])
    def health():
        try:
            from utils.db import client

            client.admin.command("ping")
            mongo_status = "connected"
        except Exception:
            mongo_status = "disconnected"

        cfg_status = Config.validate()
        b2_status = "connected" if cfg_status["b2_configured"] else "not_configured"

        return jsonify(
            {
                "success": True,
                "status": "Backend running",
                "mongo": mongo_status,
                "storage": b2_status,
                "environment": Config.ENV,
                "endpoints": [
                    f"POST {API_PREFIX}/register",
                    f"POST {API_PREFIX}/login",
                    f"POST {API_PREFIX}/logout",
                    f"GET {API_PREFIX}/me",
                    f"POST {API_PREFIX}/change-password",
                    f"POST {API_PREFIX}/upload",
                    f"GET {API_PREFIX}/files",
                    f"GET {API_PREFIX}/download/<file_id>",
                    f"POST {API_PREFIX}/download/<file_id>",
                    f"GET {API_PREFIX}/download-url/<file_id>",
                    f"DELETE {API_PREFIX}/files/<file_id>",
                    f"POST {API_PREFIX}/keys/register",
                    f"GET {API_PREFIX}/keys/me",
                    f"GET {API_PREFIX}/keys/<email>",
                    f"DELETE {API_PREFIX}/keys/me",
                    f"POST {API_PREFIX}/tokens/create",
                    f"GET {API_PREFIX}/tokens",
                    f"GET {API_PREFIX}/tokens/file/<file_id>",
                    f"DELETE {API_PREFIX}/tokens/<token_id>",
                    f"GET {API_PREFIX}/tokens/validate",
                    f"GET {API_PREFIX}/tokens/download",
                    f"GET {API_PREFIX}/access/download/<raw_token>",
                    f"POST {API_PREFIX}/shares",
                    f"GET {API_PREFIX}/shares/sent",
                    f"GET {API_PREFIX}/shares/file/<file_id>",
                    f"GET {API_PREFIX}/shares/received",
                    f"GET {API_PREFIX}/shares/<share_id>",
                    f"GET {API_PREFIX}/shares/<share_id>/download",
                    f"DELETE {API_PREFIX}/shares/<share_id>",
                    f"GET {API_PREFIX}/shares/access/<raw_token>",
                    f"GET {API_PREFIX}/admin/audit-logs",
                    f"GET {API_PREFIX}/admin/audit-logs/stats",
                    f"GET {API_PREFIX}/admin/audit-logs/verify",
                    f"GET {API_PREFIX}/admin/audit-logs/<log_id>",
                    f"GET {API_PREFIX}/admin/audit-logs/export",
                    f"GET {API_PREFIX}/health",
                ],
            }
        )

    @app.route("/", methods=["GET"])
    def root():
        return jsonify(
            {
                "success": True,
                "status": "ok",
                "health": f"{API_PREFIX}/health",
                "msg": "Secure Cloud API Ready",
            }
        )

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"success": False, "msg": "Endpoint not found"}), 404

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"success": False, "msg": "Payload too large. Exceeds upload limit."}), 413

    @app.errorhandler(429)
    def rate_limit_error(e):
        return jsonify({"success": False, "msg": "Too many requests. Please slow down."}), 429

    @app.errorhandler(500)
    def server_error(_):
        return jsonify({"success": False, "msg": "Internal server error"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=not Config.IS_PRODUCTION, host="0.0.0.0", port=port)
